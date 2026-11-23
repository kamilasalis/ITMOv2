const http = require("node:http");
const { readFile, stat } = require("node:fs/promises");
const { createReadStream } = require("node:fs");
const path = require("node:path");
const { recipes, matchMenus } = require("./recipes.js");

const files = {
  "/": ["prototype.html", "text/html; charset=utf-8"],
  "/prototype.html": ["prototype.html", "text/html; charset=utf-8"],
  "/design.html": ["design.html", "text/html; charset=utf-8"],
  "/recipes.js": ["recipes.js", "text/javascript; charset=utf-8"],
  "/food-illustrations.png": ["food-illustrations.png", "image/png"],
  "/vendor/bootstrap.min.css": ["vendor/bootstrap.min.css", "text/css; charset=utf-8"]
};
const validMeals = new Set(recipes.map(([meal]) => meal));
const validFoods = new Set(recipes.flatMap(recipe => recipe[3].map(([key]) => key)));

function sendJson(response, status, data) {
  response.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(data));
}

async function handleMenus(request, response) {
  let body = "";
  for await (const chunk of request) {
    body += chunk;
    if (body.length > 4096) {
      sendJson(response, 413, { error: "Слишком большой запрос" });
      return;
    }
  }
  let data;
  try { data = JSON.parse(body); }
  catch { return sendJson(response, 400, { error: "Некорректный запрос" }); }
  const { meals, foods } = data ?? {};
  if (!Array.isArray(meals) || !meals.length || meals.some(meal => !validMeals.has(meal)) ||
      !Array.isArray(foods) || !foods.length || foods.some(food => !validFoods.has(food))) {
    return sendJson(response, 400, { error: "Выберите приёмы пищи и продукты из каталога" });
  }
  sendJson(response, 200, { menus: matchMenus([...new Set(meals)], [...new Set(foods)]) });
}

async function handleRequest(request, response) {
  const pathname = request.url.split("?")[0];
  if (request.method === "POST" && pathname === "/api/menus") return handleMenus(request, response);
  if (request.method === "GET" && pathname === "/eggs.mp4") {
    const filename = path.join(__dirname, "eggs.mp4");
    const { size } = await stat(filename);
    response.writeHead(200, { "Content-Type": "video/mp4", "Content-Length": size });
    createReadStream(filename).pipe(response);
    return;
  }
  const asset = Object.hasOwn(files, pathname) && files[pathname];
  if (request.method === "GET" && asset) {
    const [filename, contentType] = asset;
    const data = await readFile(path.join(__dirname, filename));
    response.writeHead(200, { "Content-Type": contentType });
    response.end(data);
    return;
  }
  sendJson(response, 404, { error: "Страница не найдена" });
}

function createServer() {
  return http.createServer((request, response) => {
    handleRequest(request, response).catch(() => {
      if (response.headersSent) response.destroy();
      else sendJson(response, 500, { error: "Не удалось выполнить запрос" });
    });
  });
}

if (require.main === module) {
  const port = Number(process.env.PORT ?? 4173);
  createServer().listen(port, "127.0.0.1", () => console.log(`http://127.0.0.1:${port}`));
}
module.exports = { createServer };
