// This WinDBG script obtains the full list of device objects (named and unnamed), counts them and displays their security descriptors.
// It will be somewhat slow (a few commands per device object), but should complete in under a minute on a typical system.
// .scriptload devobj_sd_analysis.js
// dx @$scriptContents.analyzeDeviceSDs()

"use strict";

function initializeScript() {
    return [new host.apiVersionSupport(1, 7)];
}

function analyzeDeviceSDs() {
    const ctl = host.namespace.Debugger.Utility.Control;
    const log = host.diagnostics.debugLog;

    let named_sd = 0, named_nosd = 0, unnamed_sd = 0, unnamed_nosd = 0;
    let total = 0, errors = 0;
    var firstErrors = [];

    // Get Body offset from type layout (no address needed)
    var bodyOff = getFieldOffset("nt!_OBJECT_HEADER", "Body");
    if (!bodyOff) {
        log("ERROR: Cannot read OBJECT_HEADER layout. Are nt symbols loaded?\n");
        return;
    }
    //log("OBJECT_HEADER.Body offset: 0x" + bodyOff + "\n");

    var sdOff = getFieldOffset("nt!_DEVICE_OBJECT", "SecurityDescriptor");
    //log("DEVICE_OBJECT.SecurityDescriptor offset: 0x" + (sdOff || "??") + "\n");

    var drvAddrs = parseDriverAddresses();
    log("Found " + drvAddrs.length + " driver objects. Scanning device object lists...\n\n");

    for (var i = 0; i < drvAddrs.length; i++) {
        try {
            var devHex = dtReadPtr("nt!_DRIVER_OBJECT", drvAddrs[i], "DeviceObject");

            while (devHex !== "0") {
                total++;
                try {
                    var hdrHex = evalSub(devHex, bodyOff);

                    var hdr = readObjectHeader(hdrHex, devHex);

                    if (hdr.hasName && hdr.hasSD)       named_sd++;
                    else if (hdr.hasName && !hdr.hasSD)  named_nosd++;
                    else if (!hdr.hasName && hdr.hasSD)  unnamed_sd++;
                    else                                 unnamed_nosd++;
                } catch (e) {
                    errors++;
                    if (firstErrors.length < 3)
                        firstErrors.push("  hdr@0x" + hdrHex + ": " + e.toString());
                }

                devHex = dtReadPtr("nt!_DEVICE_OBJECT", devHex, "NextDevice");
            }
        } catch (e) {
            errors++;
            if (firstErrors.length < 3)
                firstErrors.push("  drv@0x" + drvAddrs[i] + ": " + e.toString());
        }
    }

    log("\n========================================\n");
    log("  Device Object SD Analysis\n");
    log("========================================\n\n");
    log("  Total device objects:      " + total + "\n\n");
    log("  Named   + SD present:      " + named_sd + "\n");
    log("  Named   + NO SD:           " + named_nosd + "\n");
    log("  Unnamed + SD present:      " + unnamed_sd + "\n");
    log("  Unnamed + NO SD:           " + unnamed_nosd + "\n\n");
    log("  Errors:                    " + errors + "\n");
    if (firstErrors.length > 0) {
        log("\n  First error(s):\n");
        for (var j = 0; j < firstErrors.length; j++) {
            log(firstErrors[j] + "\n");
        }
    }
    log("========================================\n");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Parse all driver object addresses from the \Driver object directory
function parseDriverAddresses() {
    var ctl = host.namespace.Debugger.Utility.Control;
    var addrs = [];
    for (var line of ctl.ExecuteCommand("!object \\Driver")) {
        var s = line.toString();
        var m = s.match(/([0-9a-f`]{10,20})\s+Driver\s+/i);
        if (m) {
            addrs.push(m[1].replace(/`/g, ""));
        }
    }
    return addrs;
}

// Get a field offset from the type layout (dt without an address)
// e.g. getFieldOffset("nt!_OBJECT_HEADER", "Body") -> "30"
function getFieldOffset(typeName, fieldName) {
    var ctl = host.namespace.Debugger.Utility.Control;
    for (var line of ctl.ExecuteCommand("dt " + typeName + " " + fieldName)) {
        var m = line.toString().match(/\+0x([0-9a-f]+)/i);
        if (m) return m[1];
    }
    return null;
}

// Read a pointer field from a typed structure using dt.
// Uses: dt TypeName 0xAddress FieldName
// Returns the pointer value as a hex string, or "0" for null.
function dtReadPtr(typeName, addrHex, fieldName) {
    var ctl = host.namespace.Debugger.Utility.Control;
    var cmd = "dt " + typeName + " 0x" + addrHex + " " + fieldName;
    for (var line of ctl.ExecuteCommand(cmd)) {
        var s = line.toString();
        if (s.indexOf("(null)") >= 0) return "0";
        var m = s.match(/:\s+(0x[0-9a-f`]+)/i);
        if (m) {
            var val = m[1].replace(/`/g, "").replace(/^0x/i, "").replace(/^0+/, "");
            return val || "0";
        }
    }
    return "0";
}

// Subtract two hex values using MASM arithmetic: a - b
function evalSub(aHex, bHex) {
    var ctl = host.namespace.Debugger.Utility.Control;
    for (var line of ctl.ExecuteCommand("? 0x" + aHex + " - 0x" + bHex)) {
        var m = line.toString().match(/=\s*([0-9a-f`]+)/i);
        if (m) return m[1].replace(/`/g, "");
    }
    return "0";
}

// Read OBJECT_HEADER fields using field-filtered dt (same approach as dtReadPtr).
//
// InfoMask bit 1 (0x02) = OBJECT_HEADER_NAME_INFO present = object is named
// SecurityDescriptor != 0 = SD is assigned (value is an encoded/fast-ref pointer)
function readObjectHeader(hdrHex, devHex) {
    var ctl = host.namespace.Debugger.Utility.Control;
	const log = host.diagnostics.debugLog;
	log("\nProcessing "+devHex+"\n")
    // Read InfoMask (byte) from OBJECT_HEADER to check if object is named
    var infoMask = 0;
    for (var line of ctl.ExecuteCommand("dt nt!_OBJECT_HEADER 0x" + hdrHex + " InfoMask")) {
        var m = line.toString().match(/:\s+0x([0-9a-f]+)/i);
        if (m) {
            infoMask = parseInt(m[1], 16);
            break;
        }
    }
    // Read SecurityDescriptor from DEVICE_OBJECT itself (not the OBJECT_HEADER!)
    // Device objects store their SD in _DEVICE_OBJECT.SecurityDescriptor
    var sdHex = dtReadPtr("nt!_DEVICE_OBJECT", devHex, "SecurityDescriptor");

	if(sdHex !== "0") // Read and display the SD
	{
		var cmd = "!sd " + sdHex
		for (var line of ctl.ExecuteCommand(cmd)) {
			log(line)
		}
		log("\n")
	}
    return {
        hasName: (infoMask & 0x2) !== 0,
        hasSD:   sdHex !== "0"
    };
}
