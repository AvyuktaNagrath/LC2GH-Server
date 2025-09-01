export function extFor(lang = "") {
  const L = lang.toLowerCase();
  if (L.includes("python")) return "py";
  if (L.includes("java ")) return "java";
  if (L === "java") return "java";
  if (L.includes("cpp") || L.includes("c++")) return "cpp";
  if (L === "c") return "c";
  if (L.includes("c#")) return "cs";
  if (L.includes("javascript") || L === "js" || L.includes("node")) return "js";
  if (L.includes("typescript") || L === "ts") return "ts";
  if (L.includes("go")) return "go";
  if (L.includes("rust")) return "rs";
  if (L.includes("kotlin")) return "kt";
  if (L.includes("swift")) return "swift";
  if (L.includes("ruby")) return "rb";
  if (L.includes("php")) return "php";
  return "txt";
}
