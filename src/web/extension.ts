/*---------------------------------------------------------
 * Copyright (C) Microsoft Corporation. All rights reserved.
 *--------------------------------------------------------*/

import * as vscode from 'vscode';
import { activateImartDebug } from '../activateImartDebug';

export function activate(context: vscode.ExtensionContext) {
	activateImartDebug(context);
}

export function deactivate() {
	// nothing to do
}
