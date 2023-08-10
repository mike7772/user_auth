import UserController from "../Controller/UserController";
const User = require("../models/mongo.model");
const userController = new UserController();

module.exports = {
  Query: {
    hello: () => {
      return "Hello World";
    },
    getAllUsers: async () => {
      return await User.find();
    },
    getUser: userController.getUser,
  },
  Mutation: {
    createUser: userController.createUser,
    login: userController.login,
    logout: userController.logout,
    changePassword: userController.changePassword,
    generateOTP: userController.generateOTP,
    verifyOTP: userController.verifyOTP,
    validateOTP: userController.validateOTP,
    disableOTP: userController.disableOTP,
  },
};
