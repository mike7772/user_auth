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
  const app = express(); // initializing the express server

  const apolloServer = new ApolloServer({
    typeDefs: typeDefs.default, //passes the schema
    resolvers, // passes the query function and mutation 
    cors: {
      origin: "http://localhot:3000",
      Credentials: true,
    },
    context: ({ req, res }: any) => ({ req, res }), // passing the req and response value to the context 
    plugins: [ApolloServerPluginLandingPageGraphQLPlayground()],  // enables the graphql playground on the local machine
  });

  await apolloServer.start(); // starting the apollo server

  apolloServer.applyMiddleware({ app: app });  // Integrate Apollo Server with Express app on /graphql (default)
  app.use(cookieParser()); // used for parsing cookies
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
