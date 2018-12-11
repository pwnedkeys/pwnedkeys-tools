guard 'rspec', cmd: "bundle exec rspec", all_on_start: true, all_after_pass: true do
  watch(%r{^spec/.+_spec\.rb$})
  watch(%r{^spec/.+_methods\.rb$}) { 'spec' }
  watch(%r{^Gemfile})              { 'spec' }
  watch('spec/spec_helper.rb')     { 'spec' }
  watch(%r{^lib/})                 { "spec" }
end
