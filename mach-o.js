function doIt(machOArray) {
    const LC_SEGMENT_64 = 0x19;
    const LC_MAIN = 0x80000028;
    const LC_UUID = 0x1b;
    const LC_VERSION_MIN_MACOSX = 0x24;
    const LC_VERSION_MIN_IPHONEOS = 0x25;
    const LC_BUILD_VERSION = 0x32;
    const LC_ENCRYPTION_INFO_64 = 0x2C;
    const LC_CODE_SIGNATURE = 0x1D;
    const LC_DYLD_INFO = 0x22;
    const LC_DYLD_INFO_ONLY = 0x80000022;
    const LC_SYMTAB = 0x2;
    const LC_DYSYMTAB = 0xB;
    const LC_LOAD_DYLIB = 0xC;
    const LC_ID_DYLIB = 0xD;
    
    let dataView = new DataView(machOArray.buffer);
    let magic = dataView.getUint32(0x0, true);
    
    if (magic !== 0xfeedfacf) {
        log(`[!] Not a valid 64-bit Mach-O file. Magic: 0x${magic.toString(16)}`);
        if (magic === 0xfeedface) {
            log(`[!] This appears to be a 32-bit Mach-O file, not 64-bit.`);
        }
        return;
    }
    
    let cputype = dataView.getUint32(0x4, true);
    let cpusubtype = dataView.getUint32(0x8, true);
    let filetype = dataView.getUint32(0xC, true);
    let ncmds = dataView.getUint32(0x10, true);
    let sizeofcmds = dataView.getUint32(0x14, true);
    let flags = dataView.getUint32(0x18, true);
    
    const cpuTypes = {
        0x7: "Intel x86",
        0x1000007: "Intel x86-64",
        0x12: "ARM",
        0x100000C: "ARM64"
    };
    
    const fileTypes = {
        0x1: "OBJECT",
        0x2: "EXECUTE",
        0x3: "FVMLIB",
        0x4: "CORE",
        0x5: "PRELOAD",
        0x6: "DYLIB",
        0x7: "DYLINKER",
        0x8: "BUNDLE",
        0x9: "DYLIB_STUB",
        0xA: "DSYM",
        0xB: "KEXT_BUNDLE"
    };
    
    log(`<h2>Mach-O Header</h2>`);
    log(`[*] Magic: 0x${magic.toString(16)} (64-bit Mach-O)`);
    log(`[*] CPU Type: ${cpuTypes[cputype] || `Unknown (0x${cputype.toString(16)})`}`);
    log(`[*] CPU Subtype: 0x${cpusubtype.toString(16)}`);
    log(`[*] File Type: ${fileTypes[filetype] || `Unknown (0x${filetype.toString(16)})`}`);
    log(`[*] Number of Load Commands: ${ncmds}`);
    log(`[*] Size of Load Commands: ${sizeofcmds} bytes`);
    log(`[*] Flags: 0x${flags.toString(16)}`);
    
    if (flags !== 0) {
        log(`<h3>Flags Details:</h3>`);
        if (flags & 0x1) log(`[*] MH_NOUNDEFS: No undefined references`);
        if (flags & 0x2) log(`[*] MH_INCRLINK: Incrementally linked`);
        if (flags & 0x4) log(`[*] MH_DYLDLINK: Linked for dyld`);
        if (flags & 0x8) log(`[*] MH_BINDATLOAD: Binds at load time`);
        if (flags & 0x10) log(`[*] MH_PREBOUND: Prebound for specific target`);
        if (flags & 0x20) log(`[*] MH_SPLIT_SEGS: Split read/write segments`);
        if (flags & 0x40) log(`[*] MH_LAZY_INIT: Lazy initialization`);
        if (flags & 0x80) log(`[*] MH_TWOLEVEL: Two-level namespace`);
        if (flags & 0x100) log(`[*] MH_FORCE_FLAT: Force flat namespace`);
        if (flags & 0x200) log(`[*] MH_NOMULTIDEFS: No multiple definitions`);
        if (flags & 0x1000) log(`[*] MH_PIE: Position Independent Executable`);
    }
    
    log(`<h2>Load Commands</h2>`);
    var offset = 32; 
    let dylibs = [];
    let foundEntitlements = false;
    
    for (let i = 0; i < ncmds; i++) {
        let cmd = dataView.getUint32(offset + 0x0, true);
        let cmdsize = dataView.getUint32(offset + 0x4, true);
        
        log(`<h3>Load Command ${i+1}: 0x${cmd.toString(16)}</h3>`);
        
        if (cmd === LC_SEGMENT_64) {
            let segname = dataView.getString(offset + 0x8, 16);
            let vmaddr = dataView.getBigInt64(offset + 0x18, true);
            let vmsize = dataView.getBigInt64(offset + 0x20, true);
            let fileoff = dataView.getBigInt64(offset + 0x28, true);
            let filesize = dataView.getBigInt64(offset + 0x30, true);
            let maxprot = dataView.getUint32(offset + 0x38, true);
            let initprot = dataView.getUint32(offset + 0x3C, true);
            let nsects = dataView.getUint32(offset + 0x40, true);
            let flags = dataView.getUint32(offset + 0x44, true);
            
            log(`[*] Segment Name: ${segname}`);
            log(`[*] VM Address: 0x${vmaddr.toString(16)}`);
            log(`[*] VM Size: 0x${vmsize.toString(16)}`);
            log(`[*] File Offset: 0x${fileoff.toString(16)}`);
            log(`[*] File Size: 0x${filesize.toString(16)}`);
            log(`[*] Maximum VM Protection: 0x${maxprot.toString(16)}`);
            log(`[*] Initial VM Protection: 0x${initprot.toString(16)}`);
            log(`[*] Number of Sections: ${nsects}`);
            log(`[*] Flags: 0x${flags.toString(16)}`);
            
            if (nsects > 0) {
                log(`<h4>Sections in ${segname}:</h4>`);
                let sectOffset = offset + 0x48; 
                
                for (let j = 0; j < nsects; j++) {
                    let sectname = dataView.getString(sectOffset, 16);
                    let segname = dataView.getString(sectOffset + 0x10, 16);
                    let addr = dataView.getBigInt64(sectOffset + 0x20, true);
                    let size = dataView.getBigInt64(sectOffset + 0x28, true);
                    
                    log(`[*] Section ${j+1}: ${sectname} (${segname})`);
                    log(`    Address: 0x${addr.toString(16)}, Size: 0x${size.toString(16)}`);
                    
                    sectOffset += 80; 
                }
            }
            
            if (segname === "__LINKEDIT") {
                log(`<h4>Found __LINKEDIT Segment</h4>`);
                let magicOff = dataView.findSequenceInRange([0xFA, 0xDE, 0x0C, 0xC0], Number(fileoff), Number(fileoff + filesize));
                
                if (magicOff !== -1) {
                    log(`[*] Code Signature Magic Found at: 0x${magicOff.toString(16)}`);
                    var blobOff = magicOff + 0xC;
                    
                    for (let i = 0; i < dataView.getUint32(magicOff + 8, false); i++) {
                        if (dataView.getUint32(blobOff, false) === 5) {
                            let entitlementsOff = magicOff + 0x8 + dataView.getUint32(blobOff + 0x4, false);
                            let entitlementsEndOff = magicOff + 0x8 + dataView.getUint32(blobOff + 0xC, false) - 8;
                            
                            log(`[*] Entitlements Offset: 0x${entitlementsOff.toString(16)}`);
                            log(`[*] Entitlements End Offset: 0x${entitlementsEndOff.toString(16)}`);
                            
                            let entitlements = dataView.getString(entitlementsOff, entitlementsEndOff - entitlementsOff);
                            log(`<h4>Entitlements:</h4>`);
                            log(`<pre>${formatXML(entitlements)}</pre>`);
                            foundEntitlements = true;
                            break;
                        }
                        blobOff += 8;
                    }
                    
                    if (!foundEntitlements) {
                        log(`[!] No entitlements found in code signature.`);
                    }
                } else {
                    log(`[!] Code signature magic not found in __LINKEDIT segment.`);
                }
            }
        } else if (cmd === LC_MAIN) {
            let entryoff = dataView.getBigInt64(offset + 0x8, true);
            let stacksize = dataView.getBigInt64(offset + 0x10, true);
            
            log(`[*] LC_MAIN - Entry Point`);
            log(`[*] Entry Point Offset: 0x${entryoff.toString(16)}`);
            log(`[*] Stack Size: 0x${stacksize.toString(16)}`);
        } else if (cmd === LC_UUID) {
            let uuid = [];
            for (let j = 0; j < 16; j++) {
                uuid.push(dataView.getUint8(offset + 0x8 + j).toString(16).padStart(2, '0'));
            }
            
            let formattedUUID = `${uuid.slice(0, 4).join('')}-${uuid.slice(4, 6).join('')}-${uuid.slice(6, 8).join('')}-${uuid.slice(8, 10).join('')}-${uuid.slice(10).join('')}`;
            
            log(`[*] LC_UUID`);
            log(`[*] UUID: ${formattedUUID}`);
        } else if (cmd === LC_BUILD_VERSION) {
            let platform = dataView.getUint32(offset + 0x8, true);
            let minos = dataView.getUint32(offset + 0xC, true);
            let sdk = dataView.getUint32(offset + 0x10, true);
            
            const platforms = {
                1: "macOS",
                2: "iOS",
                3: "tvOS",
                4: "watchOS",
                5: "bridgeOS",
                6: "macCatalyst",
                7: "iOSSimulator",
                8: "tvOSSimulator",
                9: "watchOSSimulator"
            };
            
            let platformName = platforms[platform] || `Unknown (${platform})`;
            let formatVersion = (version) => {
                let major = (version >> 16) & 0xFFFF;
                let minor = (version >> 8) & 0xFF;
                let patch = version & 0xFF;
                return `${major}.${minor}.${patch}`;
            };
            
            log(`[*] LC_BUILD_VERSION`);
            log(`[*] Platform: ${platformName}`);
            log(`[*] Minimum OS Version: ${formatVersion(minos)}`);
            log(`[*] SDK Version: ${formatVersion(sdk)}`);
        } else if (cmd === LC_ENCRYPTION_INFO_64) {
            let cryptoff = dataView.getUint32(offset + 0x8, true);
            let cryptsize = dataView.getUint32(offset + 0xC, true);
            let cryptid = dataView.getUint32(offset + 0x10, true);
            
            log(`[*] LC_ENCRYPTION_INFO_64`);
            log(`[*] Encryption Offset: 0x${cryptoff.toString(16)}`);
            log(`[*] Encryption Size: 0x${cryptsize.toString(16)}`);
            log(`[*] Encryption ID: ${cryptid} (${cryptid === 0 ? "Not encrypted" : "Encrypted"})`);
        } else if (cmd === LC_LOAD_DYLIB) {
            let nameOffset = dataView.getUint32(offset + 0x8, true);
            let timestamp = dataView.getUint32(offset + 0xC, true);
            let current_version = dataView.getUint32(offset + 0x10, true);
            let compatibility_version = dataView.getUint32(offset + 0x14, true);
            
            let name = dataView.getString(offset + nameOffset, 256); 
            dylibs.push(name);
            
            log(`[*] LC_LOAD_DYLIB`);
            log(`[*] Library: ${name}`);
            log(`[*] Timestamp: ${new Date(timestamp * 1000).toISOString()}`);
            log(`[*] Current Version: 0x${current_version.toString(16)}`);
            log(`[*] Compatibility Version: 0x${compatibility_version.toString(16)}`);
        } else {
            log(`[*] Command Type: 0x${cmd.toString(16)}`);
            log(`[*] Command Size: ${cmdsize} bytes`);
        }
        
        offset += cmdsize;
    }
    
    if (dylibs.length > 0) {
        log(`<h2>Dynamic Libraries (${dylibs.length})</h2>`);
        dylibs.forEach((lib, index) => {
            log(`[*] ${index + 1}. ${lib}`);
        });
    }
    
    // Display summary information
    log(`<h2>Summary</h2>`);
    log(`[*] File Type: ${fileTypes[filetype] || "Unknown"}`);
    log(`[*] Architecture: ${cpuTypes[cputype] || "Unknown"}`);
    if (foundEntitlements) {
        log(`[*] Contains Entitlements: Yes`);
    } else {
        log(`[*] Contains Entitlements: No`);
    }
    
    // Check for encryption
    let isEncrypted = false;
    offset = 32;
    for (let i = 0; i < ncmds; i++) {
        let cmd = dataView.getUint32(offset, true);
        let cmdsize = dataView.getUint32(offset + 4, true);
        
        if (cmd === LC_ENCRYPTION_INFO_64) {
            let cryptid = dataView.getUint32(offset + 0x10, true);
            if (cryptid !== 0) {
                isEncrypted = true;
                break;
            }
        }
        
        offset += cmdsize;
    }
    
    log(`[*] Encrypted: ${isEncrypted ? "Yes" : "No"}`);
}
function findMainEntryPoint(machOArray) {
    const LC_MAIN = 0x80000028;
    let dataView = new DataView(machOArray.buffer);
    let magic = dataView.getUint32(0x0, true);
    let ncmds = dataView.getUint32(0x10, true);
    log(`[*] magic: 0x${magic.toString(16)}`);
    log(`[*] ncmds: ${ncmds}`);
    var offset = 32;
    for (let i = 0; i < ncmds; i++) {
        let cmd = dataView.getUint32(offset + 0x0, true);
        let cmdsize = dataView.getUint32(offset + 0x4, true);
        if (cmd === LC_MAIN) {
            let entryoff = dataView.getUint32(offset + 0x8, true);
            return entryoff;
        }
        offset += cmdsize;
    }
    throw new Error(`didn't find main entry point!`);
    return 0;
}
function formatXML(xml) {
    if (!xml) return '';
    
    // Replace < with &lt; to prevent HTML rendering
    xml = xml.replace(/</g, '&lt;').replace(/>/g, '&gt;');
    
    let formatted = '';
    let indent = '';
    xml.split(/(&lt;\/.*?&gt;|&lt;.*?&gt;)/).forEach(part => {
        if (!part) return;
        
        if (part.startsWith('&lt;/')) {
            indent = indent.substring(2);
            formatted += indent + part + '\n';
        } else if (part.startsWith('&lt;') && !part.endsWith('/&gt;')) {
            formatted += indent + part + '\n';
            indent += '  ';
        } else if (part.startsWith('&lt;') && part.endsWith('/&gt;')) {
            formatted += indent + part + '\n';
        } else {
            if (part.trim()) {
                formatted += indent + part + '\n';
            }
        }
    });
    
    return formatted;
}
DataView.prototype.findSequenceInRange = function(sequence, start, end) {
    start = Math.max(0, start);
    end = Math.min(end, this.byteLength);
    if (start >= end) {
        log("Invalid range: start should be less than end.");
        return -1;
    }
    for (let i = start; i <= end - sequence.length; i++) {
        let match = true;
        for (let j = 0; j < sequence.length; j++) {
            const byte = this.getUint8(i + j);
            if (byte !== sequence[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            return i;
        }
    }
    log("Sequence not found in the specified range.");
    return -1;
};
DataView.prototype.getString = function(offset, size) {
    let bytes = [];
    for (let i = 0; i < size; i++) {
        let byte = this.getUint8(offset + i);
        if (byte == 0) break;
        bytes.push(byte)
    }
    return new TextDecoder().decode(new Uint8Array(bytes));
};
function extractStringTable(machOArray) {
    const LC_SYMTAB = 0x2;
    let dataView = new DataView(machOArray.buffer);
    let ncmds = dataView.getUint32(0x10, true);
    var offset = 32; 
    
    for (let i = 0; i < ncmds; i++) {
        let cmd = dataView.getUint32(offset, true);
        let cmdsize = dataView.getUint32(offset + 4, true);
        
        if (cmd === LC_SYMTAB) {
            let stroff = dataView.getUint32(offset + 8, true);
            let strsize = dataView.getUint32(offset + 12, true);
            
            log(`<h3>String Table</h3>`);
            log(`[*] String Table Offset: 0x${stroff.toString(16)}`);
            log(`[*] String Table Size: 0x${strsize.toString(16)}`);
            
            let strings = [];
            let currentOffset = stroff;
            let endOffset = stroff + strsize;
            
            while (currentOffset < endOffset) {
                let str = dataView.getString(currentOffset, endOffset - currentOffset);
                if (str && str.length > 0) {
                    strings.push(str);
                    currentOffset += str.length + 1; 
                } else {
                    currentOffset++;
                }
            }
            
            if (strings.length > 0) {
                log(`<h4>Interesting Strings (${strings.length} total)</h4>`);
                strings.filter(s => s.length > 3).slice(0, 100).forEach((str, idx) => {
                    log(`[*] ${idx + 1}. ${str}`);
                });
                
                if (strings.length > 100) {
                    log(`[*] ... and ${strings.length - 100} more strings`);
                }
            }
            
            return;
        }
        
        offset += cmdsize;
    }
    
    log(`[!] No string table found.`);
}
