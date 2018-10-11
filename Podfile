platform :ios, '10.0'

target 'Firebase Chat iOS' do
  # Comment the next line if you're not using Swift and don't want to use dynamic frameworks
  use_frameworks!

  # Pods for Firebase Chat iOS
  pod 'Firebase/Core'
  pod 'Firebase/Auth'
  pod 'Firebase/Firestore'

  pod 'VirgilCryptoApiImpl', '~> 3.0'
  pod 'VirgilKeyknox', :git => 'https://github.com/Ogerets/keyknox-x.git'
  pod 'VirgilPythia', :git => 'https://github.com/Ogerets/pythia-x.git'

  pod 'Chatto', '~> 3.3.1'
  pod 'ChattoAdditions', '~> 3.3.1'

  pod 'PKHUD', '~> 5.0'
end

post_install do |installer|
    installer.pods_project.targets.each do |target|
        target.build_configurations.each do |config|
            config.build_settings['SWIFT_VERSION'] = '4.1'
        end
    end
end