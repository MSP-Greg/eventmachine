source 'https://rubygems.org'

gemspec

gem 'rake'

install_if -> { RUBY_VERSION > '3.1' } do
  gem 'net-smtp'
end

# ostruct is a bundled gem with Ruby 3.5 and later
if RUBY_VERSION >= '3.5'
  gem 'ostruct'
  gem 'set'
end

# only needed for lib/em/pure_ruby.rb
# switch to install_if when ruby 2.2 support is dropped
if RUBY_VERSION >= '3.0'
  gem 'sorted_set'
end

group :documentation do
  gem 'yard', '>= 0.8.5.2'
  gem 'redcarpet' unless RUBY_PLATFORM =~ /java|mswin/
end
