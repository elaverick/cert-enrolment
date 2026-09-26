// Progressive enhancement for the enrolment form. Everything works without
// it; with it, the platform is preselected from the browser and the
// illustration follows the chosen platform.
(function () {
  "use strict";

  const select = document.getElementById("platform");
  if (!select) {
    return;
  }

  // Browsers do not expose the computer's name, but they do reveal the
  // operating system. iPadOS Safari reports itself as a Mac, so a Mac with
  // a touch screen is treated as an iPad.
  function detectPlatform() {
    const ua = navigator.userAgent;
    const hint = navigator.userAgentData && navigator.userAgentData.platform;

    if (/iPhone|iPad|iPod/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1)) {
      return "ios";
    }
    if (hint === "Windows" || /Windows NT/.test(ua)) {
      return "windows";
    }
    if (hint === "Linux" || (/Linux/.test(ua) && !/Android/.test(ua))) {
      return "linux";
    }
    return null;
  }

  // The server marks the select when it has already chosen a value, such as
  // after a validation error; that choice is kept.
  if (!select.dataset.chosen) {
    const detected = detectPlatform();
    if (detected && select.querySelector('option[value="' + detected + '"]')) {
      select.value = detected;
      const note = document.getElementById("platform-detected");
      if (note) {
        note.hidden = false;
      }
    }
  }

  // Shows the illustration and naming tip for the chosen platform. The
  // illustrations are SVG, which has no hidden property, so the attribute
  // is set directly.
  function followPlatform() {
    const illustration = select.value === "ios" ? "phone" : "computer";
    document.querySelectorAll("[data-illustration]").forEach(function (element) {
      element.toggleAttribute("hidden", element.dataset.illustration !== illustration);
    });
    document.querySelectorAll("[data-tip]").forEach(function (element) {
      element.toggleAttribute("hidden", element.dataset.tip !== select.value);
    });
  }

  select.addEventListener("change", followPlatform);
  followPlatform();
})();
