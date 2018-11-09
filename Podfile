platform :ios, '10.0'

target 'Firebase Chat iOS' do
  # Comment the next line if you're not using Swift and don't want to use dynamic frameworks
  use_frameworks!

  # Pods for Firebase Chat iOS
  pod 'Firebase/Core'
  pod 'Firebase/Auth'
  pod 'Firebase/Firestore'
  pod 'Firebase/Messaging'

  pod 'VirgilE3Kit', '~> 0.1.1'

  pod 'Chatto', '~> 3.3.1'
  pod 'ChattoAdditions', '~> 3.3.1'

  pod 'PKHUD', '~> 5.0'
end

target 'Notification Extention' do
  # Comment the next line if you're not using Swift and don't want to use dynamic frameworks
  use_frameworks!

  # Pods for Notification Extention
  pod 'VirgilCryptoApiImpl', '~> 3.2.1'
  pod 'VirgilSDK', git: 'https://github.com/VirgilSecurity/sdk-x.git', branch: 'develop'

end


post_install do |installer|
    installer.pods_project.targets.each do |target|
        target.build_configurations.each do |config|
            config.build_settings['SWIFT_VERSION'] = '4.1'
        end
    end
end