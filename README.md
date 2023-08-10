#  Installation
1. Run git clone https://github.com/mike7772/user_auth.git
2. Run yarn of npm install
3. The .env file is exposed so no need to create one
   
# StartUp documentation
1. Run yarn start or npm run start the server will run in port 4000 and the the apollo graphql server is available in http://localhost:4000/graphql
2. Then you can access the mutation by 
  - createUser (user: {fullName: "" email: "" password: ""}){ fullName} you set set the response as you like
  - login (user: { email: "email"  password: "password"}) { token} 
  - logout (user: { email: "email"}) { fullName}
  - changePassword (user: {email: "" oldPassword: "" password: ""}){}
  - generateOTP (user: {email: ""}){}       generate the secret key and qrcode which enables the user to access the authenticator apps
  - verifyOTP (user: {email: "" otpToken: ""}) {}    enable the 2FA feature and return a success message
  - validateOTP (user: {email: "" otpToken: ""}) {}  handles OTP verification action where you will be required to provide the OTP token to verify your identity.
  - disableOTP (user: {email: "" }) {}    disable 2fa authentication
  - removeUser (user: {email: "" }) {}

3. The protected routes won't work unless the user logs in.
