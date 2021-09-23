/* eslint-disable @typescript-eslint/naming-convention */
/*---------------------------------------------------------
 * Copyright (C) Microsoft Corporation. All rights reserved.
 *--------------------------------------------------------*/

import {
	Logger, logger,
	LoggingDebugSession, ThreadEvent,
	InitializedEvent, TerminatedEvent, StoppedEvent, BreakpointEvent, OutputEvent,
    InvalidatedEvent,
	Thread, StackFrame, Scope, Source, Handles, Breakpoint, ErrorDestination, Variable
} from 'vscode-debugadapter';
import { DebugProtocol } from 'vscode-debugprotocol';
import { basename, normalize } from 'path';
import { Subject } from 'await-notify';
import { Transform, TransformCallback } from 'stream';
import { createConnection, Socket } from 'net';
import {StringDecoder} from 'string_decoder';
import * as URL from 'url';
import * as FS from 'fs';
import * as vscode from 'vscode';
import { FileAccessor } from './imartRuntime';

interface CommonArguments {
	/**
	 * Typically the workspace root. localRoot is used to construct a relative path
	 * for source files that are also present in the remoteRoot.
	 * Thus, this argument is not used when files are transpiled and have sourcemaps. See sourceMaps argument.
	 */
	localRoot?: string;
	/**
	 * The default root path of JavaScript files in a remote environment. Used to resolve
	 * files in the VS Code local file system to files in a remote file system.
	 */
	remoteRoot?: string
	address: string;
	port: number;
	console?: ConsoleType;
	/** enable logging the Debug Adapter Protocol */
	trace?: boolean;
	hack?: boolean;
}

/**
 * This interface describes the imart-debug specific launch attributes
 * (which are not part of the Debug Adapter Protocol).
 * The schema for these attributes lives in the package.json of the imart-debug extension.
 * The interface should always match this schema.
 */
interface ILaunchRequestArguments extends CommonArguments, DebugProtocol.LaunchRequestArguments {
	/** run without debugging */
	noDebug?: boolean;
	/** if specified, results in a simulated compile error in launch. */
	compileError?: 'default' | 'show' | 'hide';
}

interface AttachRequestArguments extends CommonArguments, DebugProtocol.AttachRequestArguments {

}
const CRLF = '\r\n';

interface PendingResponse {
	resolve: Function;
	reject: Function;
}

type HitterFunction = (hitCount: number) => boolean;

class InternalSourceBreakpoint {
	id: number;
	line: number;
	orgLine: number;
	column: number;
	orgColumn: number;
	condition: string | undefined;
	hitCount: number;
	hitter: HitterFunction | undefined;
	verificationMessage!: string;
	breakpointId?: number;

	constructor(id: number, line: number, column: number = 0, condition?: string, logMessage?: string, hitter?: HitterFunction) {
		this.id = id;
		this.line = this.orgLine = line;
		this.column = this.orgColumn = column;

		if (logMessage) {
			this.condition = logMessageToExpression(logMessage);
			if (condition) {
				this.condition = `(${condition}) && ${this.condition}`;
			}
		} else if (condition) {
			this.condition = condition;
		}

		this.hitCount = 0;
		this.hitter = hitter;
	} 
}
const LOGMESSAGE_VARIABLE_REGEXP = /{(.*?)}/g;

function logMessageToExpression(msg: string) {

	msg = msg.replace(/%/g, '%%');

	let args: string[] = [];
	let format = msg.replace(LOGMESSAGE_VARIABLE_REGEXP, (match, group) => {
		const a = group.trim();
		if (a) {
			args.push(`(${a})`);
			return '%s';
		} else {
			return '';
		}
	});

	format = format.replace(/'/g, '\\\'');

	if (args.length > 0) {
		return `Debug.print(Format.get('${format}', ${args.join(', ')})) && false`;
	}
	return `Debug.print(Format.get('${format}')) && false`;
}
interface RhinoFrame {
	
	scopeName: string,
	contextId: number,
	ref: number,
	threadId: number,
	line: number,
	frameId: number,
	scriptId: number
}

interface RhinoVariable {
	frame: number;
	ref: number;
	type: string;
	className?: string;
	constructorFunction?: number;
	prototypeObject?: number;
	value?: string|number|boolean;
	name?: string;
	properties: Array<RhinoVarProperty>;
}
interface RhinoVarProperty {
	ref: number;
	name: string|number;
}
interface Script {
	scriptId: number;
	source: string;
	location: string;
	properties: Array<any>;
	generated: boolean;
	lines: Array<number>;
	functions: Array<string>;
}
interface RhinoBreakEvent {
	breakpoint?: number;
	contextId:number;
	debuggerStatement:boolean;
	line:number;
	scriptId:number;
	threadId:number;
	functionName?:string;
	step?: string;
}
interface RhinoBreakpoint {
	breakpointId: number;
	scriptId: number;
	line: number;
	function?: string;
	condition?: string;
	threadId?: number;
}
/**
 * Messages from the qjs binary are in big endian length prefix json payloads.
 * The protocol is roughly just the JSON stringification of the requests.
 * Responses are intercepted to translate references into thread scoped references.
 */
 class MessageParser extends Transform {
	private _rawData: string = '';
	private decoder = new StringDecoder('utf8');
	private _contentLength = -1;
	constructor() {
		super();
	}
	_transform(chunk: Buffer, encoding: string, cb: TransformCallback): void {
		this._rawData += this.decoder.write(chunk);
		while(true) {
			if (this._contentLength >= 0) {
				if (this._rawData.length >= this._contentLength) {
					const message = this._rawData.substring(0, this._contentLength);
					this._rawData = this._rawData.slice(this._contentLength);
					this._contentLength = -1;
					if (message.length > 0) {
						try {
							this.emit('message', JSON.parse(message));
						}
						catch (e) {
						}
					}
					continue; // three may be more complete messages to process; 
				}
			} else {
				const idx = this._rawData.indexOf(CRLF);
				if (idx !== -1) {
					const length = this._rawData.substring(0, idx);
					this._contentLength = parseInt(length, 10);
					this._rawData = this._rawData.slice(idx + CRLF.length);
					continue;	// try to handle a complete message
				}
			}
			break;
		}
		cb();
	}
}
type ConsoleType = 'internalConsole' | 'integratedTerminal' | 'externalTerminal';

export class ImartDebugSession extends LoggingDebugSession {

	private _configurationDone = new Subject();
	private _useInvalidatedEvent = false;

	/***************
	 * IMART 定义开始
	 */
	private static HITCOUNT_MATCHER = /(>|>=|=|==|<|<=|%)?\s*([0-9]+)/;
	private _threads = new Set<number>();
	private _connection?: Socket;
	private _requests = new Map<number, PendingResponse>();
	private _isTerminated: boolean;
	private _commonArgs!: CommonArguments;
	private _argsSubject = new Subject();
	private _scripts = new Map<number, Script>();	// script cache
	private _pathToScript = new Map<string, Script>();	// script cache
	private _localRoot?: string;
	private _remoteRoot?: string;
	private _argsReady = (async () => {
		await this._argsSubject.wait();
	})();
	private _seq: number = 1;
	private _version: any = {};
	private _breakpointId = 1;
	private _breakpoints = new Map<string, InternalSourceBreakpoint[]>();
	private _stopOnException: boolean = false;
	private _stopExceptionMessage?: string;


	private _exception: any;


	// state valid between stop events
	private _variableHandles = new Handles<RhinoVariable>();
	private _frameHandles = new Handles<RhinoFrame>();
	private _refCache = new Map<number, RhinoVariable>();
	static PROTO: string = 'prototypeObject';
	
	/**
	 * Creates a new debug adapter that is used for one debug session.
	 * We configure the default implementation of a debug adapter here.
	 */
	public constructor(fsAccessor: FileAccessor) {
		super("imart-debug.txt");
		this._isTerminated = false;
		// this debugger uses zero-based lines and columns
		this.setDebuggerLinesStartAt1(true);
		this.setDebuggerColumnsStartAt1(true);
	}

	/**
	 * The 'initialize' request is the first request called by the frontend
	 * to interrogate the features the debug adapter provides.
	 */
	protected initializeRequest(response: DebugProtocol.InitializeResponse, args: DebugProtocol.InitializeRequestArguments): void {

		if (args.supportsInvalidatedEvent) {
			this._useInvalidatedEvent = true;
		}

		// build and return the capabilities of this debug adapter:
		response.body = response.body || {};

		// the adapter implements the configurationDone request.
		response.body.supportsConfigurationDoneRequest = true;

		// make VS Code use 'evaluate' when hovering over source
		response.body.supportsEvaluateForHovers = true;

		// make VS Code support completion in REPL
		response.body.supportsCompletionsRequest = true;
		response.body.completionTriggerCharacters = [ ".", "[" ];

		// the adapter defines two exceptions filters, one with support for conditions.
		response.body.supportsExceptionFilterOptions = true;
		// This debug adapter supports two exception breakpoint filters
		response.body.exceptionBreakpointFilters = [
			{
				label: "All Exceptions",
				filter: 'all',
				default: false
			},
			{
				label: "Message Filter Exceptions",
				filter: 'filter',
				default: false,
				supportsCondition: true,
				conditionDescription: `Enter the exception's message`
			}
		];
		

		// make VS Code send exceptionInfo request
		response.body.supportsExceptionInfoRequest = true;

		response.body.supportsTerminateRequest = true;
		// This debug adapter supports conditional breakpoints.
		response.body.supportsConditionalBreakpoints = true;
		response.body.supportsHitConditionalBreakpoints = true;
		response.body.supportsLogPoints = true;

		this.sendResponse(response);

		// since this debug adapter can accept configuration requests like 'setBreakpoint' at any time,
		// we request them early by sending an 'initializeRequest' to the frontend.
		// The frontend will end the configuration sequence by calling 'configurationDone' request.
		this.sendEvent(new InitializedEvent());
	}

	/**
	 * Called at the end of the configuration sequence.
	 * Indicates that all breakpoints etc. have been sent to the DA and that the 'launch' can start.
	 */
	protected configurationDoneRequest(response: DebugProtocol.ConfigurationDoneResponse, args: DebugProtocol.ConfigurationDoneArguments): void {
		super.configurationDoneRequest(response, args);

		// notify the launchRequest that configuration has finished
		this._configurationDone.notify();
	}
	protected async attachRequest(response: DebugProtocol.AttachResponse, args: AttachRequestArguments, request?: DebugProtocol.Request) {
		this._commonArgs = args;
		this._commonArgs.address = args.address || 'localhost';
		this._localRoot = args.localRoot;
		this._remoteRoot = args.remoteRoot;
		this._argsSubject.notify();
		// wait until configuration has finished (and configurationDoneRequest has been called)
		await this._configurationDone.wait(1000);

		this.beforeConnection({});
		this.afterConnection();
		this.sendResponse(response);
	}
	protected async launchRequest(response: DebugProtocol.LaunchResponse, args: ILaunchRequestArguments) {

		// make sure to 'Stop' the buffered logging if 'trace' is not set
		logger.setup(args.trace ? Logger.LogLevel.Verbose : Logger.LogLevel.Stop, false);
		this._commonArgs = args;
		this._commonArgs.address = args.address || 'localhost';
		this._localRoot = args.localRoot;
		this._remoteRoot = args.remoteRoot;

		this._argsSubject.notify();

		// wait until configuration has finished (and configurationDoneRequest has been called)
		await this._configurationDone.wait(1000);

		let env = {};
		try {
			this.beforeConnection(env);
		}
		catch (e: any) {
			this.sendErrorResponse(response, 17, e.message);
			return;
		}
		if (typeof args.console === 'string') {
			switch (args.console) {
				case 'internalConsole':
				case 'integratedTerminal':
				case 'externalTerminal':
					break;
				default:
					this.sendErrorResponse(response, 2028, `Unknown console type '${args.console}'.`);
					return;
			}
		}
		try {
			this.afterConnection();
		}
		catch (e: any) {
			this.sendErrorResponse(response, 18, e.message);
			return;
		}
		if (args.compileError) {
			// simulate a compile/build error in "launch" request:
			// the error should not result in a modal dialog since 'showUser' is set to false.
			// A missing 'showUser' should result in a modal dialog.
			this.sendErrorResponse(response, {
				id: 1001,
				format: `compile error: some fake error.`,
				showUser: args.compileError === 'show' ? true : (args.compileError === 'hide' ? false : undefined)
			});
		} else {
			this.sendResponse(response);
		}
	}
	private async _handleBreakEvent(event: RhinoBreakEvent) {
		if (event.breakpoint && !event.step && !event.debuggerStatement) {
			let script = this._scripts.get(event.scriptId);
			if (script) {
				let relPath = this._getRemoteRelativePath(script.location);
				const bps = this._getBreakpointsOfPath(relPath);
				let bp = bps.find(bp => bp.breakpointId === event.breakpoint);
				if (bp) {
					bp.hitCount++;
					if (bp.hitter && !bp.hitter(bp.hitCount)) {
						this.sendThreadRequest('continue', {threadId: event.threadId});
						return;
					}
					if (bp.condition) {
						let threadId = event.threadId;
						let frames = (await this.sendThreadRequest('frames', {threadId})).frames as Array<number>; 
						let frameId = frames[0];
						let rv = (await this.sendThreadRequest('evaluate', {expression: bp.condition, threadId, frameId})).evaluate;
						if (!rv || (!rv.value && !rv.properties)) {
							this.sendThreadRequest('continue', {threadId: event.threadId});
							return;
						}
					}
				}
			}
		}
		this.sendEvent(new StoppedEvent("break", event.threadId));
	}
	private handleEvent(event: any) {
		if (event.event === 'break') {
			this._stopped();
			this._handleBreakEvent(event.body);
		}
		else if (event.event === 'vmdeath') {
			this._terminated('remote terminated');
		}
		else if (event.event === "thread") {
			let thread: number = event.body.threadId;
			let reason = {enter: 'new', exit: 'exited'}[event.body.type];
			const threadEvent = new ThreadEvent(reason, thread);
			if (threadEvent.body.reason === 'new')
				{this._threads.add(thread);}
			else if (threadEvent.body.reason === 'exited')
				{this._threads.delete(thread);}
			this.sendEvent(threadEvent);
		} else if (event.event === "script") {
			let scriptId = event.body.scriptId;
			this._loadScript(scriptId).then(s => {
				this._scripts.set(s.scriptId, s);
				return s;
			}).then(async s => {
				await this._setPendingBreakpoint(s);
				let step = ((await this.getArguments()).hack || event.body.supportPrev) ? 'prev' : null;
				this.sendThreadRequest('continue', {
					threadId: event.body.threadId,
					step
				});
			});
		} else if (event.event === "exception") {
			let message = event.body.message;
			this._exception = event.body;
			if (this._stopOnException || (this._stopExceptionMessage && message.indexOf(this._stopExceptionMessage) >= 0)) {
				this._stopped();
				this.sendEvent(new StoppedEvent("exception", event.body.threadId, message));
			} else {
				this.sendThreadRequest("continue", {threadId: event.body.threadId});
			}
		}
	}
/**
	 * clear everything that is no longer valid after a new stopped event.
	 */
 	private _stopped(): void {
		this._exception = undefined;
		this._variableHandles.reset();
		this._frameHandles.reset();
		this._refCache = new Map<number, RhinoVariable>();
	}

	private _loadScript(scriptId: number): Promise<Script> {
		return this.sendThreadRequest('script', {scriptId}).then(resp => {
			let script = resp.script as Script;
			let relPath = this._getRemoteRelativePath(script.location);
			this._pathToScript.set(relPath, script);
			return script;
		});
	}
	private async _setPendingBreakpoint(script: Script) {
		let relPath = this._getRemoteRelativePath(script.location);
		if (relPath) {
			const bps = this._getBreakpointsOfPath(relPath);
			for (let i = bps.length -1; i>=0; i-=1) {
				let bp = bps[i];
				let rbp = (await this._setBreakpoint(script.scriptId, bp.line, bp.condition)).breakpoint as RhinoBreakpoint;
				if (rbp) 
				{
					let {line, breakpointId} = rbp;
					bp.line = line;
					bp.breakpointId = breakpointId;
					this.sendEvent(new BreakpointEvent('changed', { verified: true, id: bp.id, line: this.convertDebuggerLineToClient(line) } as DebugProtocol.Breakpoint));
				} else {
					this.sendEvent(new BreakpointEvent('removed', { verified: true, id: bp.id } as DebugProtocol.Breakpoint));
					bps.splice(i, 1);
				}
			}
		}
	}
	private _getRemoteRelativePath(path: string): string {
		// first convert urls to paths
		const u = URL.parse(path);
		if (u.protocol === 'file:' || u.protocol === 'rhino:' && u.path) {
			// a local file path
			path = decodeURI(u.path!);
		}
		return makeRelative2(this._getRemoteRoot(path), path);
	}
	private _getLocalRelativePath(path: string): string {
		if(this._localRoot) {
			return makeRelative2(path_normalize(this._localRoot), path);
		}
		return path;
	}
	private _getRemoteRoot(path?: string): string {
		if (this._remoteRoot) {
			return this._remoteRoot;
		} else if(path) {
			let spliter = 'WEB-INF/jssp';
			let idx = path.indexOf(spliter);
			if (idx >= 0) {
				let root = path.substring(0, idx + spliter.length);
				this._remoteRoot = root;
				return root;
			}
		} 
		throw new Error("unknown remote root");
	}
	private handleResponse(json: any) {
		let requestSeq: number = json.request_seq;
		let pending = this._requests.get(requestSeq);
		if (!pending) {
			this.logTrace(`request not found: ${requestSeq}`);
			return;
		}
		
		this._requests.delete(requestSeq);
		if (!json.success)
			{pending.reject(new Error(json.message));}
		else
			{pending.resolve(json.body);}
	}

	private async newSession() {
		this._seq = 1;
		this._isTerminated = false;
		await this.sendThreadRequest('connect', {});
		let version = await this.sendThreadRequest('version', {});
		this._version = version;

		let scriptIds = (await this.sendThreadRequest('scripts', {})).scripts as Array<number>;
		let scripts = await Promise.all(scriptIds.map(id => this._loadScript(id)));
		scripts.forEach(s => {
			this._scripts.set(s.scriptId, s);
			this._setPendingBreakpoint(s);
		});
	}

	private onSocket(socket: Socket) {
		this.closeConnection();
		this._connection = socket;

		let parser = new MessageParser();
		parser.on('message', json => {
			// the very first message will include the thread id, as it will be a stopped event.
			if (json.type === 'event') {
				const thread = json.body.threadId;
				if (thread && !this._threads.has(thread)) {
					this._threads.add(thread);
					this.sendEvent(new ThreadEvent("new", thread));
					this.emit('quickjs-thread');
				}
				this.logTrace(`received message: ${JSON.stringify(json)}`);
				this.handleEvent(json);
			}
			else if (json.type === 'response') {
				this.logTrace(`received response: ${JSON.stringify(json)}`);
				this.handleResponse(json);
			}
			else {
				this.logTrace(`unknown message ${json.type}`);
			}
		});

		socket.pipe(parser as any);
		socket.on('error', e => this._terminated(e.toString()));
		socket.on('close', () => this._terminated('close'));
		this.newSession();
	}

	private beforeConnection(env: any) {
		// make sure to 'Stop' the buffered logging if 'trace' is not set
		logger.setup(this._commonArgs.trace ? Logger.LogLevel.Verbose : Logger.LogLevel.Stop, false);
		if (!this._commonArgs.port)
			{throw new Error("Must specify a 'port' for 'connect'");}
	}

	private async afterConnection() {

		let socket: Socket | undefined = undefined;
		for (let attempt = 0; attempt < 10; attempt++) {
			try {
				socket = await new Promise<Socket>((resolve, reject) => {
					let socket = createConnection(this._commonArgs.port, this._commonArgs.address);
					socket.on('connect', () => {
						socket.removeAllListeners();
						resolve(socket);
					});

					socket.on('close', reject);
					socket.on('error', reject);
				});
				break;
			}
			catch (e) {
				await new Promise(resolve => setTimeout(resolve, 1000));
			}
		}

		if (!socket) {
			const address = this._commonArgs.address || 'localhost';
			throw new Error(`Cannot launch connect (${address}:${this._commonArgs.port}).`);
		}

		this.onSocket(socket);
	}
	protected async setBreakPointsRequest(response: DebugProtocol.SetBreakpointsResponse, args: DebugProtocol.SetBreakpointsArguments): Promise<void> {

		response.body = {
			breakpoints: []
		};

		this.logTrace(`setBreakPointsRequest: ${JSON.stringify(args)}`);

		const path = args.source.path as string;
		if (!path) {
			this.sendResponse(response);
			return;
		}
		// set and verify breakpoint locations
		let relPath = this._getLocalRelativePath(path);
		let sbs = this._getBreakpointsOfPath(relPath);

		// clear all breakpoints for this file
		await this._clearBreakpoints(sbs);
		this._breakpoints.set(relPath, sbs = []);
		if (args.breakpoints) {

			for(let b of args.breakpoints) {
				let hitter: HitterFunction | undefined;
				if (b.hitCondition) {
					const result = ImartDebugSession.HITCOUNT_MATCHER.exec(b.hitCondition.trim());
					if (result && result.length >= 3) {
						let op = result[1] || '>=';
						if (op === '=') {
							op = '==';
						}
						const value = result[2];
						const expr = op === '%'
							? `return (hitcnt % ${value}) === 0;`
							: `return hitcnt ${op} ${value};`;
						hitter = <HitterFunction> Function('hitcnt', expr);
					} else {
						// error
					}
				}

				sbs.push(new InternalSourceBreakpoint(
					this._breakpointId++,
					this.convertClientLineToDebugger(b.line),
					typeof b.column === 'number' ? this.convertClientColumnToDebugger(b.column) : 0,
					b.condition, b.logMessage, hitter)
				);
			}
		} else if (args.lines) {
			// deprecated API: convert line number array
			for (let l of args.lines) {
				sbs.push(new InternalSourceBreakpoint(this._breakpointId++, this.convertClientLineToDebugger(l)));
			}
		}

		const actualBreakpoints: Array<DebugProtocol.Breakpoint> = [];
		const deleteIds: Array<number> = [];
		for (var i = sbs.length - 1; i >= 0; i -= 1) {
			let l = sbs[i];
			let script = this._pathToScript.get(relPath);
			if (script) {
				let rbp = (await this._setBreakpoint(script.scriptId, l.line, l.condition)).breakpoint as RhinoBreakpoint;
				if (rbp) {
					let {line, breakpointId} = rbp;
					l.line = line;
					l.breakpointId = breakpointId;
					const bp = new Breakpoint(true, this.convertDebuggerLineToClient(line)) as DebugProtocol.Breakpoint;
					bp.id= l.id;
					actualBreakpoints.push(bp);
				} else {
					sbs.splice(i, 1);
					const bp = new Breakpoint(false, this.convertDebuggerLineToClient(l.line)) as DebugProtocol.Breakpoint;
					bp.id = l.id;
					bp.line = -1;
					l.verificationMessage = "can not set to this line";
					actualBreakpoints.push(bp);
					deleteIds.push(bp.id);
				}
			} else {
				const bp = new Breakpoint(false, this.convertDebuggerLineToClient(l.line)) as DebugProtocol.Breakpoint;
				bp.id = l.id;
				l.verificationMessage = "waiting for script load";
				actualBreakpoints.push(bp);
			}
		}
		// send back the actual breakpoint positions
		response.body = {
			breakpoints: actualBreakpoints.reverse()
		};
		this.sendResponse(response);

		deleteIds.forEach(id => this.sendEvent(new BreakpointEvent("removed", {id} as DebugProtocol.Breakpoint)));
	}
	private _getBreakpointsOfPath(relPath: string) {
		let sbs = this._breakpoints.get(relPath);
		if (!sbs) {
			sbs = new Array<InternalSourceBreakpoint>();
			this._breakpoints.set(relPath, sbs);
		}
		return sbs;
	}

	private async _setBreakpoint(scriptId: number, line: number, condition?: string) {
		return this.sendThreadRequest('setbreakpoint', {scriptId, line, condition});
	}
	private async _clearBreakpoints(bps: Array<InternalSourceBreakpoint>) {
		let clearedList: Array<Promise<any>> = [];
		bps.forEach(async bp => {
			if (bp.breakpointId) {
				clearedList.push(this.sendThreadRequest('clearbreakpoint', {breakpointId: bp.breakpointId}).catch(e => {}));
			}
		});
		await Promise.all(clearedList);
	}

	protected async setExceptionBreakPointsRequest(response: DebugProtocol.SetExceptionBreakpointsResponse, args: DebugProtocol.SetExceptionBreakpointsArguments): Promise<void> {
		this._stopOnException = false;
		this._stopExceptionMessage = undefined;
		if (args.filterOptions) {
			for (const filterOption of args.filterOptions) {
				switch (filterOption.filterId) {
					case 'all':
						this._stopOnException = true;
						break;
					case 'filter':
						this._stopExceptionMessage = filterOption.condition;
						break;
				}
			}
		}
		this.sendResponse(response);
	}

	protected exceptionInfoRequest(response: DebugProtocol.ExceptionInfoResponse, args: DebugProtocol.ExceptionInfoArguments) {
		if (this._exception) {
			response.body = {
			exceptionId: 'undefined',
			description: this._exception.message,
			breakMode: 'always',
			details: {
					message: this._exception.message,
				}
			};
			this.sendResponse(response);
		} else {
			this.sendErrorResponse(response, 2032, 'exceptionInfoRequest error: no stored exception', undefined, ErrorDestination.Telemetry);
		}
	}
		

	protected async threadsRequest(response: DebugProtocol.ThreadsResponse): Promise<void> {
		response.body = {
			threads: Array.from(this._threads.keys()).map(thread => new Thread(thread, `${this?._version['javascript.vm.vender']} thread 0x${thread.toString(16)}`))
		};
		this.sendResponse(response);
	}

	protected async stackTraceRequest(response: DebugProtocol.StackTraceResponse, args: DebugProtocol.StackTraceArguments) {
		const threadId = args.threadId;

		let frames = (await this.sendThreadRequest('frames', {threadId})).frames as Array<number>; 
		response.body = {
			stackFrames: await Promise.all(frames.map(async (fId, ix) => {
				let frame = (await this.sendThreadRequest('frame', {threadId, frameId: fId})).frame as RhinoFrame;
				let frameReference = this._frameHandles.create(frame);
				let script = this._scripts.get(frame.scriptId);
				if (script) {
					let name = this._getFrameName(frame);
					const sf: DebugProtocol.StackFrame = new StackFrame(frameReference, name, this._createSource(script), this.convertDebuggerLineToClient(frame.line));
					return sf;
				} else {
					throw new Error("script not found");
				}
			})),
			totalFrames: frames.length		// stk.count is the correct size, should result in a max. of two requests
		};
		this.sendResponse(response);
	}

	protected sourceRequest(response: DebugProtocol.SourceResponse, args: DebugProtocol.SourceArguments): void {

		// first try to use 'source.sourceReference'
		if (args.source && args.source.sourceReference) {
			let script = this._scripts.get(args.source.sourceReference);
			if (script) {		// script content already cached
				response.body = {
					content: script.source,
					mimeType: 'text/javascript'
				};
				this.sendResponse(response);
				return;
			}
		}
		this.sendErrorResponse(response, 2026, "Could not retrieve content.");
	}
	
	private _createSource(script: Script): Source {
		let relPath = this._getRemoteRelativePath(script ? script.location: '');
		let localPath = path_join(this._localRoot || '', relPath);
		let sourceReference : number|undefined = undefined;
		if (process.platform === 'win32') {	// local is Windows
			localPath = toWindows(localPath);
		}
		if (!FS.existsSync(localPath)) {
			sourceReference = script.scriptId;
		}
		return new Source(basename(localPath), localPath, sourceReference, undefined, 'imart-adapter-data');
	}

	private _getFrameName(frame: RhinoFrame) {
		let script = this._scripts.get(frame.scriptId);
		let relPath = this._getRemoteRelativePath(script ? script.location: '');
		return basename(relPath);
	}
	protected async scopesRequest(response: DebugProtocol.ScopesResponse, args: DebugProtocol.ScopesArguments) {
		let frame = this._frameHandles.get(args.frameId);
		if (!frame) {
			this.sendErrorResponse(response, 2020, 'stack frame not valid', null, ErrorDestination.Telemetry);
			return;
		}
		let {frameId, threadId, ref} = frame;
		let variable = (await this.sendThreadRequest('lookup', {
			frameId, threadId, ref
		})).lookup as RhinoVariable;
		variable.frame = args.frameId;

		this._refCache.set(ref, variable);
		let varReference = this._variableHandles.create(variable);
		let scopes = [new Scope("Vars", varReference, false)];
		response.body = {
			scopes
		};
		this.sendResponse(response);
	}

	protected async variablesRequest(response: DebugProtocol.VariablesResponse, args: DebugProtocol.VariablesArguments, request?: DebugProtocol.Request) {
		const variablesContainer = this._variableHandles.get(args.variablesReference);
		if (variablesContainer) {
			// in case of error return empty variables array
			let {threadId, frameId} = this._frameHandles.get(variablesContainer.frame);

			let vars = await Promise.all(variablesContainer.properties.map(async p => {
				try {
					let v = this._refCache.get(p.ref) || (await this.sendThreadRequest('lookup', {threadId, frameId, ref: p.ref})).lookup as RhinoVariable;
					v.frame = variablesContainer.frame;
					this._refCache.set(p.ref, v);
					return this.convertFromRuntime( '' + p.name, v);
				} catch (e: any) {
					let dapVariable: DebugProtocol.Variable = {
						name: '' + p.name,
						value: e.message,
						type: 'string',
						variablesReference: 0,
					};
					return dapVariable;
				}
			}));
			response.body = {
				variables: vars.sort(ImartDebugSession.compareVariableNames)
			};
			this.sendResponse(response);
		} else {
			// no container found: return empty variables array
			response.body = {
				variables: []
			};
			this.sendResponse(response);
		}
	}

	protected continueRequest(response: DebugProtocol.ContinueResponse, args: DebugProtocol.ContinueArguments): void {
		this.sendThreadRequest('continue', {threadId: args.threadId});
		this.sendResponse(response);
	}

	protected nextRequest(response: DebugProtocol.NextResponse, args: DebugProtocol.NextArguments): void {
		this.sendThreadRequest('continue', {threadId: args.threadId, step: 'next'});
		this.sendResponse(response);
	}

	protected stepInRequest(response: DebugProtocol.StepInResponse, args: DebugProtocol.StepInArguments): void {
		this.sendThreadRequest('continue', {threadId: args.threadId, step: 'in'});
		this.sendResponse(response);
	}

	protected stepOutRequest(response: DebugProtocol.StepOutResponse, args: DebugProtocol.StepOutArguments): void {
		this.sendThreadRequest('continue', {threadId: args.threadId, step: 'out'});
		this.sendResponse(response);
	}

	protected async evaluateRequest(response: DebugProtocol.EvaluateResponse, args: DebugProtocol.EvaluateArguments): Promise<void> {

		let reply: string | undefined;
		let rv: RhinoVariable | undefined;

		switch (args.context) {
			case 'repl':
				// handle some REPL commands:
				// 'evaluate' supports to create and delete breakpoints from the 'repl':
				let matches = /new +([0-9]+)/.exec(args.expression);
				if (matches && matches.length === 2) {
					reply = "breakpoint create failed";
					if (vscode.window.activeTextEditor) {
						let path = vscode.window.activeTextEditor.document.uri.fsPath;
						let relPath = this._getLocalRelativePath(path);
						let sbs = this._getBreakpointsOfPath(relPath);
						let bp = new InternalSourceBreakpoint(
							this._breakpointId++,
							this.convertClientLineToDebugger(parseInt(matches[1])),
							);
						let script = this._pathToScript.get(relPath);
						if (script) {
							let rbp = (await this._setBreakpoint(script.scriptId, bp.line)).breakpoint as RhinoBreakpoint;
							if (rbp) {
								let {line, breakpointId} = rbp;
								bp.line = line;
								bp.breakpointId = breakpointId;
								const cbp = new Breakpoint(true, this.convertDebuggerLineToClient(line), 0, new Source("", path)) as DebugProtocol.Breakpoint;
								cbp.id= bp.id;
								this.sendEvent(new BreakpointEvent('new', cbp));
								sbs.push(bp);
								reply = `breakpoint created`;
							} 
						}
						
					}
				} else {
				    matches = /del +([0-9]+)/.exec(args.expression);
					if (matches && matches.length === 2) {
						let line = this.convertClientLineToDebugger(parseInt(matches[1]));
						if (vscode.window.activeTextEditor) {
							let path = vscode.window.activeTextEditor.document.uri.fsPath;
							let relPath = this._getLocalRelativePath(path);
							let sbs = this._getBreakpointsOfPath(relPath);
							let idx = sbs.findIndex(bp => bp.line === line);
							if (idx >= 0) {
								let bp = sbs[idx];
								if (bp.breakpointId) {
									await this.sendThreadRequest('clearbreakpoint', {breakpointId: bp.breakpointId}).catch(e => {});
									sbs.splice(idx, 1);
									const cbp = new Breakpoint(false) as DebugProtocol.Breakpoint;
									cbp.id= bp.id;
									this.sendEvent(new BreakpointEvent('removed', cbp));
									reply = `breakpoint deleted`;
								}
							}
						}
					} else {
						matches = /refresh +(vars)/.exec(args.expression);
						if (matches && matches.length === 2) {
							this._refCache.clear();
							this.sendEvent(new InvalidatedEvent( ['variables']));
							reply = 'Variables refreshed';
						}
					}
				}
				if (matches) {
					break;
				}
			default:
				if (args.frameId) {
					let {threadId, frameId} = this._frameHandles.get(args.frameId);
					rv = (await this.sendThreadRequest('evaluate', {expression: args.expression, threadId, frameId})).evaluate as RhinoVariable;
					if (rv) {
						rv.frame = args.frameId;
						this._refCache.set(rv.ref, rv);
					}
				}
			  break;
		}

		if (rv) {
			const v = this.convertFromRuntime("$eval", rv);
			response.body = {
			 	result: v.value,
			 	type: v.type,
			 	variablesReference: v.variablesReference
			};
		} else {
			response.body = {
				result: reply ? reply : `evaluate(context: '${args.context}', '${args.expression}')`,
				variablesReference: 0
			};
		}

		this.sendResponse(response);
		if (args.context === 'repl' && this._useInvalidatedEvent && /[^!=]=[^!=]/.exec(args.expression)) {
			this._refCache.clear();
			this.sendEvent(new InvalidatedEvent( ['variables']));
		}
	}

	protected completionsRequest(response: DebugProtocol.CompletionsResponse, args: DebugProtocol.CompletionsArguments): void {
		response.body = {
			targets: [
				{
					label: "new <line>",
					selectionStart: 4,
					selectionLength: 6,
					sortText: "01"
				},
				{
					label: "del <line>",
					selectionStart: 4,
					selectionLength: 6,
					sortText: "02"
				},
				{
					label: "refresh vars",
					selectionStart: 6,
					sortText: "03"
				}
				
			]
		};
		if (args.frameId) {
			let frame = this._frameHandles.get(args.frameId);
			let frameScope = this._refCache.get(frame.ref);
			if (frameScope) {
				frameScope.properties.forEach((p, idx)=> {
					response.body.targets.push({label: p.name.toString(), sortText: '' + (10 + idx)});
				});
			}
			
		}
		this.sendResponse(response);
	}

	//---- helpers
	private convertFromRuntime(name: string, v: RhinoVariable): DebugProtocol.Variable {

		let dapVariable: DebugProtocol.Variable = {
			name: name,
			value: '???',
			type: v.type,
			variablesReference: 0,
			evaluateName: name
		};
		let varReference = this._variableHandles.create(v);
				
		switch (v.type) {
			case 'number':
				dapVariable.value = v.value !== undefined && v.value !== null ? v.value.toString() : '' + v.value;
				dapVariable.type = 'number';
				break;
			case 'string':
				dapVariable.value = `"${v.value}"`;
				break;
			case 'boolean':
				dapVariable.value = v.value ? 'true' : 'false';
				break;
			case 'null':
				dapVariable.value = 'Null';
				break;
			case 'object':
			case 'function':
			case 'array':
				dapVariable.value = v.className || v.type;
				dapVariable.variablesReference = varReference;
				break;
			default:
				dapVariable.value = v.className || v.type;
				break;		
		}

		return dapVariable;
	}

	async getArguments(): Promise<CommonArguments> {
		await this._argsReady;
		return this._commonArgs;
	}

	public async logTrace(message: string) {
		await this._argsReady;
		if (this._commonArgs.trace)
			{this.log(message);}
	}

	public log(message: string) {
		this.sendEvent(new OutputEvent(message + '\n', 'console'));
	}

	private _terminated(reason: string): void {
		this.log(`Debug Session Ended: ${reason}`);
		if (this._connection) {
			let clear: Array<Promise<any>> = [];
			this._breakpoints.forEach((v, k) => {
				clear.concat(v.map(bp => this.sendThreadRequest('clearbreakpoint', {breakpointId : bp.breakpointId}).catch(() => {})));
			});
			Promise.all(clear).then(() => 
				this.sendThreadRequest('continue', {}).catch(() => {})
			).then(() => {
				this.sendThreadRequest('dispose', {}).catch(() => {});
			}).then(() => this.closeConnection());
		}
		
		if (!this._isTerminated) {
			this._isTerminated = true;
			this.sendEvent(new TerminatedEvent());
		}
	}

	private async closeConnection() {
		if (this._connection)
			{this._connection.destroy();}
		this._connection = undefined;
		this._threads.clear();
	}

	protected disconnectRequest(response: DebugProtocol.DisconnectResponse, args: DebugProtocol.DisconnectArguments): void {
		this._terminated("disconnected");
		this.sendResponse(response);
	}
	protected async terminateRequest(response: DebugProtocol.TerminateResponse, args: DebugProtocol.TerminateArguments, request?: DebugProtocol.Request) {
		this._terminated("stopped");
		this.sendResponse(response);
	}
	private sendThreadMessage(envelope: any) {
		if (!this._connection) {
			this.logTrace(`debug connection not avaiable`);
			return;
		}

		this.logTrace(`sent: ${JSON.stringify(envelope)}`);

		let json = JSON.stringify(envelope);

		let jsonBuffer = Buffer.from(json, 'utf8');

		let messageLength = json.length;
		let length = messageLength.toString(10);
		let lengthBuffer = Buffer.from(length);
		let crlf = Buffer.from(CRLF);
		let buffer = Buffer.concat([lengthBuffer, crlf, jsonBuffer]);
		this._connection.write(buffer);
	}

	private sendThreadRequest(command: string, args: any): Promise<any> {
		let request_seq = this._seq++;
		
		return new Promise((resolve, reject) => {
			// todo: don't actually need to cache this. can send across wire.
			this._requests.set(request_seq, {
				resolve,
				reject,
			});

			let envelope = {
				type: 'request',
				command,
				seq: request_seq,
				arguments: args
			};

			this.sendThreadMessage(envelope);
		});
	}

	// /**
	//  * Tries to map a (local) VSCode path to a corresponding path on a remote host (where node is running).
	//  * The remote host might use a different OS so we have to make sure to create correct file paths.
	//  */
	// private _localToRemote(localPath: string) : string {
	// 	if (this._remoteRoot && this._localRoot) {

	// 		let relPath = PathUtils.makeRelative2(this._localRoot, localPath);
	// 		let remotePath = PathUtils.join(this._remoteRoot, relPath);

	// 		if (/^[a-zA-Z]:[\/\\]/.test(this._remoteRoot)) {	// Windows
	// 			remotePath = PathUtils.toWindows(remotePath);
	// 		}

	// 		this.log(`_localToRemote: ${localPath} -> ${remotePath}`);

	// 		return remotePath;
	// 	} else {
	// 		return localPath;
	// 	}
	// }

	// /**
	//  * Tries to map a path from the remote host (where node is running) to a corresponding local path.
	//  * The remote host might use a different OS so we have to make sure to create correct file paths.
	//  */
	// private _remoteToLocal(remotePath: string) : string {
	// 	if (this._remoteRoot && this._localRoot) {

	// 		let relPath = PathUtils.makeRelative2(this._remoteRoot, remotePath);
	// 		let localPath = PathUtils.join(this._localRoot, relPath);

	// 		if (process.platform === 'win32') {	// local is Windows
	// 			localPath = PathUtils.toWindows(localPath);
	// 		}

	// 		this.log(`_remoteToLocal: ${remotePath} -> ${localPath}`);

	// 		return localPath;
	// 	} else {
	// 		return remotePath;
	// 	}
	// }


	private static compareVariableNames(v1: Variable, v2: Variable): number {
		let n1 = v1.name;
		let n2 = v2.name;

		if (n1 === ImartDebugSession.PROTO) {
			return 1;
		}
		if (n2 === ImartDebugSession.PROTO) {
			return -1;
		}

		// convert [n], [n..m] -> n
		n1 = ImartDebugSession.extractNumber(n1);
		n2 = ImartDebugSession.extractNumber(n2);

		const i1 = parseInt(n1);
		const i2 = parseInt(n2);
		const isNum1 = !isNaN(i1);
		const isNum2 = !isNaN(i2);

		if (isNum1 && !isNum2) {
			return 1;		// numbers after names
		}
		if (!isNum1 && isNum2) {
			return -1;		// names before numbers
		}
		if (isNum1 && isNum2) {
			return i1 - i2;
		}
		return n1.localeCompare(n2);
	}

	private static extractNumber(s: string): string {
		if (s[0] === '[' && s[s.length-1] === ']') {
			return s.substring(1, s.length - 1);
		}
		return s;
	}
}

/**
 * Return the relative path between 'from' and 'to'.
 */
function makeRelative2(from: string, to: string): string {

	from = path_normalize(from);
	to = path_normalize(to);

	const froms = from.substr(1).split('/');
	const tos = to.substr(1).split('/');

	while (froms.length > 0 && tos.length > 0 && froms[0] === tos[0]) {
		froms.shift();
		tos.shift();
	}

	let l = froms.length - tos.length;
	if (l === 0) {
		l = tos.length - 1;
	}

	while (l > 0) {
		tos.unshift('..');
		l--;
	}
	return tos.join('/');
}
/**
 * Convert the given Windows or Unix-style path into a normalized path that only uses forward slashes and has all superflous '..' sequences removed.
 * If the path starts with a Windows-style drive letter, a '/' is prepended.
 */
function path_normalize(p: string) : string {

	p = p.replace(/\\/g, '/');
	if (/^[a-zA-Z]\:\//.test(p)) {
		p = '/' + p[0].toUpperCase() + p.substr(1);
	}
	p = normalize(p);	// use node's normalize to remove '<dir>/..' etc.
	p = p.replace(/\\/g, '/');
	return p;
}
/**
 * Append the given relative path to the absolute path and normalize the result.
 */
function path_join(absPath: string, relPath: string) : string {
	absPath = path_normalize(absPath);
	relPath = path_normalize(relPath);
	if (absPath.charAt(absPath.length-1) === '/') {
		absPath = absPath + relPath;
	} else {
		absPath = absPath + '/' + relPath;
	}
	absPath = path_normalize(absPath);
	absPath = absPath.replace(/\\/g, '/');
	return absPath;
}

function toWindows(path: string) : string {
	if (/^\/[a-zA-Z]\:\//.test(path)) {
		path = path.substr(1);
	}
	path = path.replace(/\//g, '\\');
	return path;
}