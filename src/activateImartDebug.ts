/*---------------------------------------------------------
 * Copyright (C) Microsoft Corporation. All rights reserved.
 *--------------------------------------------------------*/

'use strict';

import * as vscode from 'vscode';
import { WorkspaceFolder, DebugConfiguration, ProviderResult, CancellationToken } from 'vscode';
import { ImartDebugSession } from './imartDebug';
import { FileAccessor } from './imartRuntime';

export function activateImartDebug(context: vscode.ExtensionContext, factory?: vscode.DebugAdapterDescriptorFactory) {

	context.subscriptions.push(
		
		vscode.commands.registerCommand('extension.imart-debug.debugEditorContents', (resource: vscode.Uri) => {
			let targetResource = resource;
			if (!targetResource && vscode.window.activeTextEditor) {
				targetResource = vscode.window.activeTextEditor.document.uri;
			}
			if (targetResource) {
				vscode.debug.startDebugging(undefined, {
					type: 'imart',
					name: 'Debug Imart',
					request: 'attach',
					localRoot: "${workspaceFolder}/src/main/jssp",
					port: 9000
				});
			}
		})
	);

	// register a configuration provider for 'imart' debug type
	const provider = new ImartConfigurationProvider();
	context.subscriptions.push(vscode.debug.registerDebugConfigurationProvider('imart', provider));

	// register a dynamic configuration provider for 'imart' debug type
	context.subscriptions.push(vscode.debug.registerDebugConfigurationProvider('imart', {
		provideDebugConfigurations(folder: WorkspaceFolder | undefined): ProviderResult<DebugConfiguration[]> {
			return [
				{
					name: "Imart debug",
					request: "attach",
					type: "imart",
					port: 9000,
					localRoot: "${workspaceFolder}/src/main/jssp",
					program: "${file}"
				}
			];
		}
	}, vscode.DebugConfigurationProviderTriggerKind.Dynamic));

	if (!factory) {
		factory = new InlineDebugAdapterFactory();
	}
	context.subscriptions.push(vscode.debug.registerDebugAdapterDescriptorFactory('imart', factory));
	if ('dispose' in factory) {
		context.subscriptions.push(factory);
	}

	// // override VS Code's default implementation of the "inline values" feature"
	// context.subscriptions.push(vscode.languages.registerInlineValuesProvider('javascript', {

	// 	provideInlineValues(document: vscode.TextDocument, viewport: vscode.Range, context: vscode.InlineValueContext) : vscode.ProviderResult<vscode.InlineValue[]> {

	// 		const allValues: vscode.InlineValue[] = [];

	// 		for (let l = viewport.start.line; l <= context.stoppedLocation.end.line; l++) {
	// 			const line = document.lineAt(l);
	// 			var regExp = /([a-z][a-z0-9_]*)[^.\(]/ig;	// variables are words starting with '$'
	// 			do {
	// 				var m = regExp.exec(line.text);
	// 				if (m) {
	// 					const varName = m[1];
	// 					const varRange = new vscode.Range(l, m.index, l, m.index + varName.length);
	// 					// some literal text
	// 					//allValues.push(new vscode.InlineValueText(varRange, `${varName}: ${viewport.start.line}`));

	// 					// value found via variable lookup
	// 					allValues.push(new vscode.InlineValueVariableLookup(varRange, varName, true));

	// 					// value determined via expression evaluation
	// 					//allValues.push(new vscode.InlineValueEvaluatableExpression(varRange, varName));
	// 				}
	// 			} while (m);
	// 		}

	// 		return allValues;
	// 	}
	// }));
}


class ImartConfigurationProvider implements vscode.DebugConfigurationProvider {

	/**
	 * Massage a debug configuration just before a debug session is being launched,
	 * e.g. add all missing attributes to the debug configuration.
	 */
	resolveDebugConfiguration(folder: WorkspaceFolder | undefined, config: DebugConfiguration, token?: CancellationToken): ProviderResult<DebugConfiguration> {

		// if launch.json is missing or empty
		if (!config.type && !config.request && !config.name) {
			const editor = vscode.window.activeTextEditor;
			if (editor && editor.document.languageId === 'javascript') {
				config.type = 'imart';
				config.name = 'Imart Debug';
				config.request = 'attach';
				config.port = 9000;
				config.localRoot = "${workspaceFolder}/src/main/jssp";
			}
		}
		return config;
	}
}

export const workspaceFileAccessor: FileAccessor = {
	async readFile(path: string) {
		try {
			const uri = vscode.Uri.file(path);
			const bytes = await vscode.workspace.fs.readFile(uri);
			const contents = Buffer.from(bytes).toString('utf8');
			return contents;
		} catch(e) {
			try {
				const uri = vscode.Uri.parse(path);
				const bytes = await vscode.workspace.fs.readFile(uri);
				const contents = Buffer.from(bytes).toString('utf8');
				return contents;
			} catch (e) {
				return `cannot read '${path}'`;
			}
		}
	}
};

class InlineDebugAdapterFactory implements vscode.DebugAdapterDescriptorFactory {

	createDebugAdapterDescriptor(_session: vscode.DebugSession): ProviderResult<vscode.DebugAdapterDescriptor> {
		return new vscode.DebugAdapterInlineImplementation(new ImartDebugSession(workspaceFileAccessor));
	}
}
