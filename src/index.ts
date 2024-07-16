import express from "express";
import {
  Sequelize,
} from "sequelize";

const app = express();
app.use(express.json());

const sequelize = new Sequelize(
  "postgres://postgres:example@auth-service-postgres:5432/postgres"
);

sequelize
  .authenticate()
  .then(() => console.log("DB connection established."))
  .catch((e) => {
    console.error("Unable to connect to the database:", e);
    process.exit(1);
  });

app.listen(4000, () => {
  console.log("Auth service running on port 4000");
});

export { sequelize, app };
import './login'
import './register'
import './check'
