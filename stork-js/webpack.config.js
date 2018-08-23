const MiniCssExtractPlugin = require('mini-css-extract-plugin');

module.exports = {
    entry: './src/Flock.js',
    output: {
        filename: './bundle.js'
    },
    mode: 'development',
    module: {
        rules: [
            {
                test: /\.js$/,
                exclude: /node_modules/,
                use: {
                    loader: 'babel-loader',
                    options: {
                        presets: ['env']
                    }
                }
            },
            {
                test: /\.(s?)css$/,
                exclude: /node_modules/,
                use: [ MiniCssExtractPlugin.loader, 'css-loader',
                       {
                           loader: 'postcss-loader', // Run post css actions
                           options: {
                               plugins: function () { // post css plugins, can be exported to postcss.config.js
                                   return [
                                       require('precss'),
                                       require('autoprefixer')
                                   ];
                               }
                           }
                       },
                       'sass-loader' ]
            },
        ]
    },
    plugins: [
        new MiniCssExtractPlugin({
            filename: "bundle.css"
        })
    ]
};
