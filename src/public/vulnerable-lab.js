// Intentionally unsafe sink, isolated for the vulnerable training mode.
export function renderVulnerableContent(element, content) {
  element.innerHTML = content;
}
