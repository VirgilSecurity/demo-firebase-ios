diff(){
  awk 'BEGIN{RS=ORS=" "}
       {NR==FNR?a[$0]++:a[$0]--}
       END{for(k in a)if(a[k])print k}' <(echo -n "${!1}") <(echo -n "${!2}")
}

containsElement () {
  local e match="$1"
  shift
  for e; do [[ "$e" == "$match" ]] && return 0; done
  return 1
}

rm -rf "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework"

case "${SWIFT_PLATFORM_TARGET_PREFIX}" in
    "ios")
        cp -R -p "VSCCrypto/PrebuiltFramework/iOS/${PRODUCT_NAME}.framework" "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework"
        LIPO_CLEAN_OUTPUT="x86_64 i386 armv7 armv7s arm64"
    ;;
    "macosx")
        cp -R -p "VSCCrypto/PrebuiltFramework/macOS/${PRODUCT_NAME}.framework" "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework"
        LIPO_CLEAN_OUTPUT="x86_64"
    ;;
    "tvos")
        cp -R -p "VSCCrypto/PrebuiltFramework/tvOS/${PRODUCT_NAME}.framework" "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework"
        LIPO_CLEAN_OUTPUT="x86_64 arm64"
    ;;
    "watchos")
        cp -R -p "VSCCrypto/PrebuiltFramework/watchOS/${PRODUCT_NAME}.framework" "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework"
        LIPO_CLEAN_OUTPUT="i386 x86_64 armv7k arm64_32"
    ;;
esac

echo "LIPO_CLEAN_OUTPUT: ${LIPO_CLEAN_OUTPUT}"
INCLUDED_ARCHS=( $LIPO_CLEAN_OUTPUT )
echo "INCLUDED_ARCHS: ${INCLUDED_ARCHS[@]}"
echo "VALID_ARCHS: ${VALID_ARCHS[@]}"

ARCHS_TO_EXCLUDE=$(diff INCLUDED_ARCHS[@] VALID_ARCHS[@])
echo "ARCHS_TO_EXCLUDE: ${ARCHS_TO_EXCLUDE[@]}"

for EXCLUDE_ARCH in ${ARCHS_TO_EXCLUDE[@]}
do
  if containsElement $EXCLUDE_ARCH ${INCLUDED_ARCHS[@]}; then
      echo "Excluding ${EXCLUDE_ARCH}"
      lipo -remove $EXCLUDE_ARCH -output "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/${PRODUCT_NAME}" "${BUILT_PRODUCTS_DIR}/${PRODUCT_NAME}.framework/${PRODUCT_NAME}"
  fi
done
