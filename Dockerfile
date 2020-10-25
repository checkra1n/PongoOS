FROM debian

RUN apt -y update; apt -y upgrade
RUN apt -y install automake make autoconf git wget tar xz-utils lzma libtinfo5 xxd

RUN mkdir -p /opt
RUN cd /opt; wget https://github.com/sbingner/llvm-project/releases/download/v10.0.0-1/linux-ios-arm64e-clang-toolchain.tar.lzma; mv linux-ios-arm64e-clang-toolchain.tar.lzma linux-ios-arm64e-clang-toolchain.tar.xz; xz -d linux-ios-arm64e-clang-toolchain.tar.xz; tar xvf linux-ios-arm64e-clang-toolchain.tar

ENV PATH="/opt/ios-arm64e-clang-toolchain/bin:${PATH}"

RUN mkdir -p /opt/sdks; cd /opt/sdks; \
    git clone https://github.com/xybp888/iOS-SDKs.git; \
    mkdir -p /opt/ios-arm64e-clang-toolchain/sdks; \
    ln -s /opt/sdks/iOS-SDKs/iPhoneOS12.1.2.sdk /opt/ios-arm64e-clang-toolchain/sdks/iPhoneOS.sdk

RUN ln -s /opt/ios-arm64e-clang-toolchain/bin/strip /usr/local/bin/cctools-strip

RUN mkdir -p /pongo

ENV OBF no
ENV PATH "/pongo/scripts:$PATH"

CMD ["bash", "-c", "cd /pongo; make"]
