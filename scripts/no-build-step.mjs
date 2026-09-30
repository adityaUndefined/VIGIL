// VIGIL has no build step: the app is plain static web assets served by app.py.
// This script exists because some hosting platforms require a build command.
// All Vision assets (OCR WASM, traineddata, QR decoder) are vendored under
// web/vendor and served as-is.
console.log("VIGIL: no build step required — static assets in web/ are served directly.");
