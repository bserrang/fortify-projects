import resolve from "@rollup/plugin-node-resolve";
import { getBabelOutputPlugin } from "@rollup/plugin-babel";
import builtins from "rollup-plugin-node-builtins";
import cleanup from "rollup-plugin-cleanup";
import commonjs from "rollup-plugin-commonjs";
import typescript from "rollup-plugin-typescript2";
import { terser } from "rollup-plugin-terser";

const pkg = require("./package.json");

const banner = [].join("\n");
const input = "src/index.ts";
const external = Object.keys(pkg.dependencies)
  .concat(["events"]);

// main
const main = {
  input,
  plugins: [
    typescript({
      check: true,
      clean: true,
      tsconfigOverride: {
        compilerOptions: {
          module: "ES2015",
        }
      },
    }),
  ],
  external,
  output: [
    {
      banner,
      file: pkg.main,
      format: "cjs",
    },
    {
      banner,
      file: pkg.module,
      format: "es",
    },
  ],
};

function babelOptions(ie) {
  const targets = ie
    ? { ie: "11" }
    : { chrome: "60" };
  return {
    babelrc: false,
    runtimeHelpers: true,
    presets: [
      [
        "@babel/env",
        {
          targets,
          corejs: 3,
          useBuiltIns: "entry",
        }
      ]
    ],
    plugins: [
      "@babel/proposal-class-properties",
      "@babel/proposal-object-rest-spread",
    ],
  }
}

const browserExternals = {
  "protobufjs": "protobuf",
  "ws": "WebSocket",
  "node-fetch": "fetch.bind(self)",
};
const browser = [
  {
    input,
    plugins: [
      resolve({
        mainFields: ["jsnext", "module", "main"],
        preferBuiltins: true,
      }),
      commonjs(),
      builtins({
        events: true,
      }),
      cleanup(),
      typescript({
        typescript: require("typescript"),
        check: true,
        clean: true,
        tsconfigOverride: {
          compilerOptions: {
            module: "ES2015",
          }
        },
      }),
    ],
    external: Object.keys(browserExternals),
    output: [
      {
        file: pkg["browser:es5"],
        format: "es",
        globals: browserExternals,
        plugins: [
          getBabelOutputPlugin({
            allowAllFormats: true,
            presets: [
              ["@babel/preset-env", {
                targets: {
                  chrome: "60"
                },
              }],
            ],
          }),
        ]
      },
      // ES2015
      {
        banner,
        footer: "self.WebcryptoSocket=WebcryptoSocket;",
        file: pkg["browser"],
        format: "iife",
        name: "WebcryptoSocket",
        globals: browserExternals,
        plugins: [
          getBabelOutputPlugin({
            allowAllFormats: true,
            presets: [
              ["@babel/preset-env", {
                targets: {
                  chrome: "60"
                },
              }],
            ],
          }),
        ]
      },
      {
        banner,
        footer: "self.WebcryptoSocket=WebcryptoSocket;",
        file: pkg["browser:min"],
        format: "iife",
        name: "WebcryptoSocket",
        globals: browserExternals,
        plugins: [
          getBabelOutputPlugin({
            allowAllFormats: true,
            presets: [
              ["@babel/preset-env", {
                targets: {
                  chrome: "60"
                },
              }],
            ],
          }),
          terser(),
        ]
      },
      // ES5
      {
        banner,
        file: pkg["browser:es5"],
        format: "iife",
        name: "WebcryptoSocket",
        globals: browserExternals,
        plugins: [
          getBabelOutputPlugin({
            allowAllFormats: true,
            presets: [
              ["@babel/preset-env", {
                targets: {
                  ie: "11"
                },
              }],
            ],
          }),
        ]
      },
      {
        banner,
        file: pkg["browser:es5:min"],
        format: "iife",
        name: "WebcryptoSocket",
        globals: browserExternals,
        plugins: [
          getBabelOutputPlugin({
            allowAllFormats: true,
            presets: [
              ["@babel/preset-env", {
                targets: {
                  ie: "11"
                },
              }],
            ],
          }),
          terser(),
        ]
      },
    ]
  },
]

export default [
  main,
  ...browser,
];