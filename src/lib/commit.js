export async function upsertFile(octo, owner, repo, path, content, message) {
  // get current sha if file exists
  let sha = undefined;
  try {
    const { data } = await octo.repos.getContent({ owner, repo, path });
    if (Array.isArray(data)) throw new Error("Path is a directory");
    sha = data.sha;
  } catch (e) {
    // 404 = new file; others rethrow
    if (e.status && e.status !== 404) throw e;
  }

  const encoded = Buffer.from(content, "utf8").toString("base64");
  const res = await octo.repos.createOrUpdateFileContents({
    owner, repo, path, message, content: encoded, sha
  });
  return res.data.content?.sha;
}
