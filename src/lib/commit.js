export async function upsertFile(octo, owner, repo, path, content, message) {
  let sha = undefined;
  try {
    const { data } = await octo.repos.getContent({ owner, repo, path });
    if (Array.isArray(data)) throw new Error("Path is a directory");
    sha = data.sha;
  } catch (e) {
    if (e.status && e.status !== 404) throw e;
  }

  const encoded = Buffer.from(content, "utf8").toString("base64");

  try {
    const res = await octo.repos.createOrUpdateFileContents({
      owner, repo, path, message, content: encoded, sha,
      ...(sha ? {} : { branch: "main" })
    });
    return res.data.content?.sha;
  } catch (e) {
    if (e.status === 409 || e.status === 422) {
      const { data: info } = await octo.repos.get({ owner, repo });
      const defaultBranch = info.default_branch || "main";
      const res2 = await octo.repos.createOrUpdateFileContents({
        owner, repo, path, message, content: encoded, sha,
        ...(sha ? {} : { branch: defaultBranch })
      });
      return res2.data.content?.sha;
    }
    throw e;
  }
}
