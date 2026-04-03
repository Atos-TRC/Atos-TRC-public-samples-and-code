// Run with ".scriptrun curr_image_name.js"

"use strict";
function initializeScript() {
    return [new host.apiVersionSupport(1, 7)];
}
function invokeScript() {
    var currentProcess = host.currentProcess;
    if (currentProcess) {
        var imageName = currentProcess.Name;
        host.diagnostics.debugLog("Current Process Image Name: " + imageName + "\n");
    } else {
        host.diagnostics.debugLog("No current process found.\n");
    }
}