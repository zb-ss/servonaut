"use strict";

window.startServonaut = (token) => {
  delete window.startServonaut;
  const NativeWebSocket = window.WebSocket;
  const expected = new URL("/ws", location.href);
  expected.protocol = "ws:";
  document.getElementById("terminal").dataset.sessionWebsocketUrl = expected.href;
  window.WebSocket = class extends NativeWebSocket {
    constructor(url) {
      const target = new URL(url);
      if (target.origin !== expected.origin || target.pathname !== "/ws") {
        throw new Error("Unexpected WebSocket destination");
      }
      super(url, ["servonaut-probe", `auth.${token}`]);
      token = "";
      window.WebSocket = NativeWebSocket;
    }
  };
  // Load only after native injection: upstream connects during window.onload.
  const script = document.createElement("script");
  script.src = "/textual.js";
  script.onload = () => window.onload(new Event("load"));
  document.head.appendChild(script);
};
