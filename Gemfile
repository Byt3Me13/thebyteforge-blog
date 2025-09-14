source "https://rubygems.org"

# GitHub Pages bundle (pins Jekyll, Minima, and supported plugins)
gem "github-pages", group: :jekyll_plugins

# Optional: only if you really use it
# group :jekyll_plugins do
#   gem "jekyll-include-cache"
# end

# Windows helpers are fine to keep; they are platform-gated
platforms :mingw, :x64_mingw, :mswin, :jruby do
  gem "tzinfo", ">= 1", "< 3"
  gem "tzinfo-data"
end

gem "wdm", "~> 0.1", :platforms => [:mingw, :x64_mingw, :mswin]
gem "http_parser.rb", "~> 0.6.0", :platforms => [:jruby]
