'use strict';

const path = require('path');

module.exports = {
  target: 'web',
  entry: {
    'bcoin': './bcoin.js',
    'index': './index-browser.js'
  },
  output: {
    path: __dirname,
    filename: '[name].bundle.js'
  },
  resolve: {
    modules: ['node_modules'],
    extensions: ['-browser.js', '.js', '.json']
  },
  node: {
    fs: 'empty',
    net: 'empty',
    tls: 'empty'
  }
};
