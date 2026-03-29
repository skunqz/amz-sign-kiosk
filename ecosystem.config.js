module.exports = {
  apps: [
    {
      name: "kiosk-app",
      script: "./server/app.js",
      cwd: "/opt/kiosk-app",
      env: {
        NODE_ENV: "production",
        PORT: 3000
      }
    }
  ]
};