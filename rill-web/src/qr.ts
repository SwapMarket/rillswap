/** A QR code as an inline SVG element, built from the module matrix (no HTML string injection). */
import qrcode from "qrcode-generator";

const SVG = "http://www.w3.org/2000/svg";

export function qrSvg(text: string, label: string, id = ""): SVGSVGElement {
  // Uppercase bech32 and BOLT11 fit the alphanumeric mode, which keeps the code small.
  const upper = text.toUpperCase();
  const alphanumeric = /^[0-9A-Z $%*+\-./:]*$/.test(upper);
  const code = qrcode(0, "M");
  code.addData(alphanumeric ? upper : text, alphanumeric ? "Alphanumeric" : "Byte");
  code.make();
  const size = code.getModuleCount(), margin = 2;
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", `0 0 ${size + 2 * margin} ${size + 2 * margin}`);
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", label);
  svg.setAttribute("class", "swap-qr");
  if (id) svg.id = id;
  const background = document.createElementNS(SVG, "rect");
  background.setAttribute("width", "100%"); background.setAttribute("height", "100%"); background.setAttribute("fill", "#fff");
  svg.append(background);
  let path = "";
  for (let row = 0; row < size; row++) {
    for (let column = 0; column < size; column++) {
      if (code.isDark(row, column)) path += `M${column + margin} ${row + margin}h1v1h-1z`;
    }
  }
  const modules = document.createElementNS(SVG, "path");
  modules.setAttribute("d", path); modules.setAttribute("fill", "#000");
  svg.append(modules);
  return svg;
}
