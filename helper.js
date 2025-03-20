function send(data) {
	try {
		ws.send(data);
	} catch (e) {
        void(0);
	}
}

function log(msg) {
	send(msg === undefined ? 'undefined' : msg.toString());
	
	const logElement = document.getElementById("log");
	let className = "log-entry";
	
	if (msg && msg.toString().includes("Found __LINKEDIT")) {
		className += " success";
	} else if (msg && msg.toString().includes("[*]")) {
		className += " highlight";
	} else if (msg && (msg.toString().includes("Error") || msg.toString().includes("not found"))) {
		className += " error";
	}
	
	logElement.innerHTML += `<div class="${className}">${msg}</div>`;
	logElement.scrollTop = logElement.scrollHeight;
}
