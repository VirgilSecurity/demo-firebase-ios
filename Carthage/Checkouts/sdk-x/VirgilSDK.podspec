Pod::Spec.new do |s|
  s.name                        = "VirgilSDK"
  s.version                     = "5.4.1"
  s.license                     = { :type => "BSD", :file => "LICENSE" }
  s.summary                     = "Virgil SDK for Apple devices and languages."
  s.homepage                    = "https://github.com/VirgilSecurity/sdk-x/"
  s.authors                     = { "Virgil Security" => "https://virgilsecurity.com/" }
  s.source                      = { :git => "https://github.com/VirgilSecurity/sdk-x.git", :tag => s.version }
  s.ios.deployment_target       = "8.0"
  s.osx.deployment_target       = "10.10"
  s.tvos.deployment_target      = "9.0"
  s.watchos.deployment_target   = "2.0"
  s.source_files                = 'Source/**/*.{h,m,swift}'
  s.public_header_files         = 'Source/VirgilSDK.h',
                                  'Source/KeyStorage/*.{h}',
                                  'Source/KeyStorage/iOS/*.{h}',
                                  'Source/KeyStorage/macOS/*.{h}'
  s.ios.exclude_files           = "Source/**/macOS/*.{h,m,swift}"
  s.osx.exclude_files           = "Source/**/iOS/*.{h,m,swift}"
  s.tvos.exclude_files          = "Source/**/macOS/*.{h,m,swift}"
  s.watchos.exclude_files       = "Source/**/macOS/*.{h,m,swift}"
  s.dependency "VirgilCryptoAPI", "~> 1.0"
end