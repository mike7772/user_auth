import { Request, Response } from "express";
import { ApolloServerPluginLandingPageGraphQLPlayground } from "apollo-server-core";
const express = require("express");
const cookieParser = require("cookie-parser");
const dotenv = require("dotenv");
dotenv.config();
const { ApolloServer, gql } = require("apollo-server-express");
const typeDefs = require("./schema/typeDefs");
const resolvers = require("./resolver/resolvers");
const mongoose = require("mongoose");

async function startServer() {
  const app = express();

  const apolloServer = new ApolloServer({
    typeDefs: typeDefs.default,
    resolvers,
    cors: {
      origin: "http://localhot:3000",
      Credentials: true,
    },
    context: ({ req, res }: any) => ({ req, res }),
    plugins: [ApolloServerPluginLandingPageGraphQLPlayground()],
  });

  await apolloServer.start();

  apolloServer.applyMiddleware({ app: app });
  app.use(cookieParser());
  app.use((req: Request, res: Response) => {
    res.send("Hello from apollo server");
  });

  // Database connection
  await mongoose
    .connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    })
    .then(() => {
      console.log(`mongoose Connected`);
    })
    .catch((err: any) => {
      console.log(err.message);
    });

  app.listen(process.env.PORT || 4000, () => {
    console.log("Server running on port 4000");
  });
}

startServer();
