#!/usr/bin/env rake
require 'bundler/gem_tasks'
require 'rspec/core/rake_task'

desc 'Run specs'
RSpec::Core::RakeTask.new

begin
  require 'rubocop/rake_task'
  RuboCop::RakeTask.new
rescue LoadError
  task :rubocop do
    warn 'Rubocop is disabled'
  end
end

namespace :sinatra do
  task :start do
    system 'bundle exec shotgun' \
           ' --server=thin --port=3000' \
           ' examples/sinatra/config.ru'
  end
end

desc 'Run specs'
task default: %i[spec rubocop]
task test: :spec
task :guard do
  system 'bundle exec guard'
end
