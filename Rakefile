exec(*(["bundle", "exec", $PROGRAM_NAME] + ARGV)) if ENV['BUNDLE_GEMFILE'].nil?

task default: :test
task default: :doc_stats

begin
  Bundler.setup(:default, :development)
rescue Bundler::BundlerError => e
  $stderr.puts e.message
  $stderr.puts "Run `bundle install` to install missing gems"
  exit e.status_code
end

require 'yard'

YARD::Rake::YardocTask.new :doc do |yardoc|
  yardoc.files = %w{lib/**/*.rb - README.md CONTRIBUTING.md CODE_OF_CONDUCT.md}
end

task :doc_stats do
  sh "yard stats --list-undoc"
end

desc "Run guard"
task :guard do
  sh "guard --clear"
end

require 'rspec/core/rake_task'
RSpec::Core::RakeTask.new :test do |t|
  t.pattern = "spec/**/*_spec.rb"
end

class Bundler::GemHelper
  def already_tagged?
    true
  end
end

Bundler::GemHelper.install_tasks
task :release do
  sh "git release"
end

namespace :docker do
  desc "Build a new docker image"
  task :build do
    sh "docker build --pull -t pwnedkeys/tools:#{GVB.version} --build-arg=GEM_VERSION=#{GVB.version} --build-arg=http_proxy=#{ENV['http_proxy']} ."
    sh "docker tag pwnedkeys/tools:#{GVB.version} pwnedkeys/tools:latest"
  end

  desc "Publish a new docker image"
  task publish: :build do
    sh "docker push pwnedkeys/tools:#{GVB.version}"
    sh "docker push pwnedkeys/tools:latest"
  end
end
