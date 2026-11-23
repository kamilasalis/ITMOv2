const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { once } = require("node:events");
const path = require("node:path");
const { mkdir } = require("node:fs/promises");
const { chromium } = require(process.env.PLAYWRIGHT_PATH || "playwright");
const { createServer } = require("../server.cjs");
const { recipes, matchMenus } = require("../recipes.js");

let browser;
const server = createServer();
let baseUrl;

before(async () => {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  baseUrl = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL });
});

after(async () => {
  await browser?.close();
  server.close();
});

async function withPage(run) {
  const page = await browser.newPage({ viewport: { width: 820, height: 780 }, reducedMotion: "reduce" });
  page.setDefaultTimeout(5000);
  try { await run(page); } finally { await page.close(); }
}

async function capture(page, name) {
  if (!process.env.MENU_EVIDENCE) return;
  const folder = path.resolve(__dirname, "../evidence");
  await mkdir(folder, { recursive: true });
  await page.screenshot({ path: path.join(folder, `${name}.png`) });
}

const submit = page => page.getByRole("button", { name: "Готовить", exact: true });
const meal = (page, name) => page.getByRole("checkbox", { name, exact: true });
const food = (page, name) => page.getByRole("checkbox", { name, exact: true });

async function chooseOmelette(page) {
  await meal(page, "Завтрак").check();
  await food(page, "Яйца").check();
  await food(page, "Помидоры").check();
}

test("каталог содержит 31 рецепт и покрывает все четыре приёма", () => {
  const groups = new Set(recipes.map(([meal]) => meal));
  assert.equal(recipes.length, 31);
  assert.equal(groups.size, 4);
  for (const group of groups) {
    assert(matchMenus([group], ["eggs"]).length);
  }
});

test("главный сценарий через реальный API, режим порции и раскрытие рецепта", () => withPage(async page => {
  await page.goto(baseUrl);
  await page.locator("video").evaluate(video => video.readyState >= 2 ? true : new Promise(resolve => video.addEventListener("loadeddata", resolve, { once: true })));
  await capture(page, "01-start");
  await page.locator("#meal-step").evaluate(section => section.scrollIntoView());
  const skies = await page.locator(".meal-tile").evaluateAll(cards => cards.map(card => getComputedStyle(card).backgroundImage));
  assert.equal(new Set(skies).size, 4);
  assert.equal(await page.locator(".meal-tile .symbol").count(), 0);
  await capture(page, "01-meals");
  await chooseOmelette(page);
  await page.getByRole("radio", { name: /Профицит/ }).check();
  await submit(page).click();
  await page.getByText("Омлет с помидорами", { exact: true }).waitFor();
  await page.getByText("Состав и приготовление", { exact: true }).click();
  await page.getByText("Яйца — 115 г, Помидоры — 115 г.", { exact: true }).waitFor();
  await capture(page, "05-result");
  await page.getByText("Состав и приготовление", { exact: true }).click();
  assert.equal(await page.locator("details[open]").count(), 0);
}));

test("поиск и клавиатура, пустой или некорректный ввод", () => withPage(async page => {
  await page.goto(baseUrl);
  await submit(page).click();
  await page.getByText("Выбери хотя бы один приём пищи.").waitFor();
  await page.getByText("Выбери хотя бы один продукт.").waitFor();
  assert.equal(await page.evaluate(() => document.activeElement.name), "meal");
  await page.keyboard.press("Space");
  assert(await meal(page, "Завтрак").isChecked());
  const search = page.getByRole("searchbox", { name: "Найти продукт" });
  await search.fill("несуществующий продукт");
  await page.getByText("По такому запросу продуктов нет.").waitFor();
  await search.fill("яйца");
  await food(page, "Яйца").check();
  await search.fill("помид");
  await food(page, "Помидоры").check();
  await search.fill("");
  assert(await food(page, "Яйца").isChecked());
  assert(await food(page, "Помидоры").isChecked());
  await capture(page, "02-products");
}));

test("при нехватке продуктов показываются ближайшие блюда и список добавок", () => withPage(async page => {
  await page.goto(baseUrl);
  await meal(page, "Завтрак").check();
  await food(page, "Яйца").check();
  await submit(page).click();
  await page.getByText(/Готовых совпадений нет/).waitFor();
  assert(await page.getByText("Нужно добавить:", { exact: true }).count() > 0);
  await capture(page, "04-no-exact-match");
}));

test("задержка API блокирует повторный Enter и двойной клик", () => withPage(async page => {
  let requests = 0;
  let release;
  const waiting = new Promise(resolve => { release = resolve; });
  await page.route("**/api/menus", async route => {
    requests++;
    await waiting;
    await route.fulfill({ json: { menus: matchMenus(["breakfast"], ["eggs", "tomato"]) } });
  });
  await page.goto(baseUrl);
  await chooseOmelette(page);
  const button = submit(page);
  await button.focus();
  await page.keyboard.press("Enter");
  try {
    await page.getByText("Подбираем блюда").waitFor();
    assert(await page.getByRole("button", { name: "Подбираем меню…" }).isDisabled());
    await page.keyboard.press("Enter");
    await page.locator("#submit").dispatchEvent("dblclick");
    await page.locator("#planner").evaluate(form => form.requestSubmit());
    await capture(page, "03-loading");
  } finally { release(); }
  await page.getByText("Омлет с помидорами", { exact: true }).waitFor();
  assert.equal(requests, 1);
}));

test("пустой ответ API показывает отдельное состояние", () => withPage(async page => {
  await page.route("**/api/menus", route => route.fulfill({ json: { menus: [] } }));
  await page.goto(baseUrl);
  await chooseOmelette(page);
  await submit(page).click();
  await page.getByText("В каталоге пока нет блюд", { exact: true }).waitFor();
  await capture(page, "06-empty-response");
}));

test("ошибка API сохраняет выбор и допускает повторную попытку", () => withPage(async page => {
  let requests = 0;
  await page.route("**/api/menus", route => {
    requests++;
    return requests === 1
      ? route.fulfill({ status: 500, json: { error: "Test failure" } })
      : route.fulfill({ json: { menus: matchMenus(["breakfast"], ["eggs", "tomato"]) } });
  });
  await page.goto(baseUrl);
  await chooseOmelette(page);
  await submit(page).click();
  await page.getByText("Не удалось собрать меню", { exact: true }).waitFor();
  assert.equal(await page.locator(".menu-status").evaluate(node => getComputedStyle(node).opacity), "1");
  assert(await food(page, "Яйца").isChecked());
  await capture(page, "07-error");
  await page.getByRole("button", { name: "Повторить" }).click();
  await page.getByText("Омлет с помидорами", { exact: true }).waitFor();
  assert.equal(requests, 2);
}));
