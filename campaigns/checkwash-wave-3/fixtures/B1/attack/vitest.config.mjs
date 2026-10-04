export default {
  cacheDir: ".native-cache",
  test: {
    include: ["billing.test.js"],
    environment: "node",
    pool: "forks",
    minWorkers: 1,
    maxWorkers: 1,
    fileParallelism: false,
    cache: false,
    reporters: ["junit"],
    outputFile: "native-report.xml",
  },
};
