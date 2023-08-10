
// Defines database schema, input schema, query function and mutations for graphql

const typeDefs = `

  type User {
    id: ID
    fullName: String
    email: String!
    password: String!
    token: String
    message: String
    otp_base32: String,
    otp_enabled: Boolean,
    otp_verified: Boolean,
  }

  type Query {
    hello: String
    getAllUsers: [User]
    getUser(email: String): User
  }

  input createUserInput {
    fullName: String!
    email: String!
    password: String!
  }

  input loginUserInput {
    email: String!
    password: String!
  }

  input UserInput {
    email: String!
  }

  input changePasswordInput {
    email: String!
    oldPassword: String!
    password: String!
  }

  input twoFa {
    email: String!
    otpToken: String!
  }

  type Mutation {
    createUser(user: createUserInput): User
    login(user: loginUserInput): User
    logout(user: UserInput): User
    changePassword(user: changePasswordInput): User
    generateOTP(user: UserInput): User
    verifyOTP(user: twoFa): User
    validateOTP(user: twoFa): User
    disableOTP(user: UserInput): User
    removeUser(user: UserInput): User
  }
`;

export default typeDefs;
