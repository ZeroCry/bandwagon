var path = require('path');
var HtmlWebPackPlugin = require('html-webpack-plugin');

var outputPath = path.join(__dirname, '/dist/');
var favIconPath = path.join(__dirname, '/src/imgs/favicon.ico');

var common = {

  entry: {
    app: ['./src/index.jsx'],
    styles: ['./src/styles/index.scss']
  },

  output: {

    publicPath: '/',

    path: outputPath,

    filename: '[name].[hash].js',

    chunkFilename: '[name].[chunkhash].js'
  },

  module: {
    loaders: [
      {
        // copies fonts to the /assets/fonts folder if used in css (url)
        test: /fonts\/(.)+\.(woff|woff2|ttf|eot|svg)/,
        loader: "url-loader?limit=10000&name=/fonts/[name].[ext]"
      },
      {
        include: path.join(__dirname, 'src'),
        test: /(\.js)|(\.jsx)$/,
        exclude: /node_modules/,
        loader: 'react-hot!babel?cacheDirectory!eslint'
      },
      {
        /*
        * copies files to a given directory and insert correct URL to them
        * (css loader calls 'require' when parsing urls within CSS which then
        * executes file-loader)
        **/
        test: /\.(png|jpg|gif)$/,
        loader: "file-loader?name=/assets/img/img-[hash:6].[ext]"
      },
      {
        test: /\.scss$/,
        loader: 'style!css!sass?outputStyle=expanded'
      }
    ]
  },
  plugins:  [
    new HtmlWebPackPlugin({
      title: 'Final step',
      favicon: favIconPath,
      inject: true
    })
 ]
};

module.exports = common;
