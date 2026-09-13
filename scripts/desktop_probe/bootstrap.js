"use strict";

window.startServonaut = (token) => {
  delete window.startServonaut;
  const NativeWebSocket = window.WebSocket;
  const expected = new URL("/ws", location.href);
  expected.protocol = "ws:";
  const terminal = document.getElementById("terminal");
  terminal.dataset.sessionWebsocketUrl = expected.href;
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
  // Measure bundled glyphs, never the OS fallback font during a cold load.
  // Keep the native entry point synchronous; WKWebView cannot serialize Promise.
  document.fonts.load(`${terminal.dataset.fontSize}px "Roboto Mono"`).then(() => {
    // Upstream connects during window.onload, after private token injection.
    const script = document.createElement("script");
    script.src = "/textual.js";
    script.onload = () => window.onload(new Event("load"));
    document.head.appendChild(script);
  }).catch(() => {
    token = "";
    window.WebSocket = NativeWebSocket;
    document.body.classList.add("-startup-error");
  });
};
