// generate_admin_hash.js
const bcrypt = require('bcryptjs'); // Make sure you have bcryptjs installed (npm install bcryptjs)

async function generateHashedPassword(plainTextPassword) {
  const saltRounds = 10; // Use the same salt rounds as in your auth controller
  const hashedPassword = await bcrypt.hash(plainTextPassword, saltRounds);
  console.log(`Plain password for admin: ${plainTextPassword}`);
  console.log(`Hashed password for admin: ${hashedPassword}`);
  return hashedPassword;
}

// IMPORTANT: Replace 'MySecretAdminPass123' with the actual password you want for your admin user.
// Choose a strong, unique password!
generateHashedPassword('MySecretAdminPass123');