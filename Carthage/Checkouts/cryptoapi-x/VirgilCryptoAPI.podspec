Pod::Spec.new do |s|
  s.name                        = "VirgilCryptoAPI"
  s.version                     = "1.0.3"
  s.license                     = { :type => "BSD", :file => "LICENSE" }
  s.summary                     = "Set of crypto interfaces needed for Virgil products"
  s.homepage                    = "https://github.com/VirgilSecurity/cryptoapi-x/"
  s.authors                     = { "Virgil Security" => "https://virgilsecurity.com/" }
  s.source                      = { :git => "https://github.com/VirgilSecurity/cryptoapi-x.git", :tag => s.version }
  s.ios.deployment_target       = "8.0"
  s.osx.deployment_target       = "10.10"
  s.tvos.deployment_target      = "9.0"
  s.watchos.deployment_target   = "2.0"
  s.source_files                = 'Source/**/*.{swift}'
end