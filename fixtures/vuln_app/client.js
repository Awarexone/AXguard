export function render(userHtml) {
  document.getElementById("out").innerHTML = userHtml;
}

export async function proxy(url) {
  return fetch(url);
}

export function runQuery(userId) {
  return db.query(`SELECT * FROM users WHERE id = ${userId}`);
}

export function compilePage(src) {
  return pug.compile(src);
}

export function saveUpload(file) {
  return save(file.originalname);
}

export function mongoFind(req) {
  return collection.find(req.body);
}

export const token = "sess-" + Math.random().toString(36);

export const graphql = {
  introspection: true,
  csrfPrevention: false,
};

export const config = {
  api_key: "pk_test_hardcoded_example_key_001",
};
