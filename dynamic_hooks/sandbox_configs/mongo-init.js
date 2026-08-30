db.createUser({
  user: "nirikshak",
  pwd: process.env.MONGO_INITDB_ROOT_PASSWORD,
  roles: [
    {
      role: "readWrite",
      db: "nirikshak_dynamic"
    }
  ]
});
