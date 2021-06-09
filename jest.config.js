module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testPathIgnorePatterns: ['/helpers/', '/node_modules/'],
  coveragePathIgnorePatterns: ['/helpers/', '/node_modules/'],
  collectCoverage: true,
  setupFilesAfterEnv: ['jest-matcher-specific-error'],
}
