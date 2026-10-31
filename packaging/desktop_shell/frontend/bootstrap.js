"use strict";

window.startServonaut = (token) => {
  delete window.startServonaut;
  const NativeWebSocket = window.WebSocket;
  const expected = new URL("/ws", location.href);
  expected.protocol = "ws:";
  const terminal = document.getElementById("terminal");
  terminal.dataset.sessionWebsocketUrl = expected.href;
  // The terminal grid rarely fills the window exactly. The app names the
  // colour of its screens, and the strip left at the edges takes it.
  const paintPage = (message) => {
    if (!Array.isArray(message) || message[0] !== "servonaut_theme") return;
    const colour = message[1] && message[1].background;
    if (typeof colour === "string" && /^#[0-9a-f]{6}$/.test(colour)) {
      document.documentElement.style.setProperty("--servonaut-page", colour);
    }
  };
  let session = null;
  // A web view opens no window for a script, so the terminal's links go to
  // the app, which opens them in the system browser. A hyperlink opens on a
  // click. An address found in plain text takes Ctrl+click (Cmd+click on
  // macOS), as in a terminal: the app may handle a click there itself.
  const openLink = (event, uri, needsModifier) => {
    if (needsModifier && !(event.ctrlKey || event.metaKey)) return;
    if (session !== null && session.readyState === NativeWebSocket.OPEN) {
      session.send(JSON.stringify(["open_url", uri]));
    }
  };
  const linkHint = /Mac/.test(navigator.userAgent)
    ? "Cmd+click to open the link"
    : "Ctrl+click to open the link";
  window.servonautTerminalLinks = Object.freeze({
    hyperlink: (event, uri) => openLink(event, uri, false),
    address: (event, uri) => openLink(event, uri, true),
    // A hyperlink's text need not be its address: say where it goes.
    hyperlinkHover: (uri) => { terminal.title = `Opens ${uri}`; },
    addressHover: () => { terminal.title = linkHint; },
    leave: () => { terminal.removeAttribute("title"); },
  });
  window.WebSocket = class extends NativeWebSocket {
    constructor(url) {
      const target = new URL(url);
      if (target.origin !== expected.origin || target.pathname !== "/ws") {
        throw new Error("Unexpected WebSocket destination");
      }
      super(url, ["servonaut.desktop.v1", `auth.${token}`]);
      token = "";
      window.WebSocket = NativeWebSocket;
      session = this;
      this.addEventListener("message", (event) => {
        if (typeof event.data !== "string") return;
        try {
          paintPage(JSON.parse(event.data));
        } catch (error) {
          // Not JSON: nothing for the page to do.
        }
      });
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
