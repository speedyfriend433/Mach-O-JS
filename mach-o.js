function doIt(machOArray) {
    const LC_SEGMENT_64 = 0x19;
    const MH_MAGIC_64 = 0xfeedfacf;
    let dataView = new DataView(machOArray.buffer);
    let magic = dataView.getUint32(0x0, true);
    let ncmds = dataView.getUint32(0x10, true);
    if (magic != MH_MAGIC_64) {
        log("[+] Not a 64-bit Mach-O!");
        return;
    }
    log(`[*] magic: 0x${magic.toString(16)}`);
    log(`[*] ncmds: ${ncmds}`);
    var offset = 32;
    for (let i = 0; i < ncmds; i++) {
        let cmd = dataView.getUint32(offset + 0x0, true);
        let cmdsize = dataView.getUint32(offset + 0x4, true);
        if (cmd === LC_SEGMENT_64) {
            let segname = dataView.getString(offset + 0x8, 16);
            let vmaddr = dataView.getBigInt64(offset + 0x18, true);
            let vmsize = dataView.getBigInt64(offset + 0x20, true);
            let fileoff = dataView.getBigInt64(offset + 0x28, true);
            let filesize = dataView.getBigInt64(offset + 0x30, true);
            log(`[*] segname: ${segname}`);
            log(`[*] vmaddr: 0x${vmaddr.toString(16)}`);
            log(`[*] vmsize: 0x${vmsize.toString(16)}`);
            log(`[*] fileoff: 0x${fileoff.toString(16)}`);
            log(`[*] filesize: 0x${filesize.toString(16)}`);
            if (segname == "__LINKEDIT") {
                log("[+] Found __LINKEDIT!!");
                let magicOff = dataView.findSequenceInRange([0xFA, 0xDE, 0x0C, 0xC0], Number(fileoff), Number(fileoff + filesize));
                log(`[*] magicOff: 0x${magicOff.toString(16)}`);
                var blobOff = magicOff + 0xC;
                for (let i = 0; i < dataView.getUint32(magicOff + 8, false); i++) {
                    if (dataView.getUint32(blobOff, false) == 5) {
                        let entitlementsOff = magicOff + 0x8 + dataView.getUint32(blobOff + 0x4, false);
                        let entitlementsEndOff = magicOff + 0x8 + dataView.getUint32(blobOff + 0xC, false) - 8;
                        log(`[*] entitlementsOff: 0x${entitlementsOff.toString(16)}`);
                        log(`[*] entitlementsEndOff: 0x${entitlementsEndOff.toString(16)}`);
                        let entitlements = dataView.getString(entitlementsOff, entitlementsEndOff - entitlementsOff);
                        log(`[*] entitlements: ${entitlements}`);
                        //log(`[*] entitlements base64: ${btoa(entitlements)}`);
                        break;
                    }
                    blobOff += 8;
                }
            }
        }
        offset += cmdsize;
    }
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
