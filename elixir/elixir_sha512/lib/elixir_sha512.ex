defmodule ElixirSha512 do
  use Bitwise

  @moduledoc false

  @spec sha512AndPrint(binary()) :: atom()
  def sha512AndPrint(message) do
    printBinaryAsHex(sha512(message), 512)
  end

  @spec sha512(binary()) :: binary()
  def sha512(message) do
    compress(hash(message))
  end

  @spec printBinaryAsHex(binary(), integer()) :: atom()
  def printBinaryAsHex(binary, bitSize) do
    <<integer :: size(bitSize)>> = binary
    :io.format("~.16#~n", [integer])
  end

  @spec hash(binary()) :: list(binary())
  def hash(message) do
    digest(preprocess(message), initialWorkers())
  end

  @spec digest(list(list(binary())), list(integer())) :: binary()
  def digest(message, initialWorkers) do
    List.foldl(message, initialWorkers, &hash_block/2)
  end

  @spec compress(list(integer())) :: integer()
  def compress(workers) do
    List.foldl(workers, <<>>, &appendBits/2)
  end

  @spec appendBits(integer(), binary()) :: binary()
  def appendBits(value, accumulator) do
    appendBits(value, accumulator, 64)
  end

  @spec appendBits(integer(), binary(), integer()) :: binary()
  def appendBits(value, accumulator, bitSize) do
    binaryValue = <<value :: size(bitSize)>>
    <<accumulator :: binary, binaryValue :: binary>>
  end

  @spec hash_block(list(binary()), list(binary())) :: list(binary())
  def hash_block(messageBlock, previousWorkers) do
    calculateWorkers(previousWorkers, calculateMessageSchedule(messageBlock))
  end

  @spec calculateWorkers(list(integer()), binary()) :: list(integer())
  def calculateWorkers(initialWorkers, messageSchedule) do
    calculateWorkers(messageSchedule, initialWorkers, initialWorkers, 0)
  end

  @spec calculateWorkers(binary(), list(integer()), list(integer()), integer()) :: list(integer())
  def calculateWorkers(_, workers, next, 80) do
    calculateIntermediateHashValue(workers, next)
  end

  def calculateWorkers(messageSchedule, workers, [a, b, c, d, e, f, g, h], t) do
    s0 = sum0(a)
    majValue = maj(a, b, c)
    t2 = add64(s0, majValue)
    s1 = sum1(e)
    chValue = ch(e, f, g)
    k = getWordFromByteOffset(kConstants(), t)
    wt = getWordFromByteOffset(messageSchedule, t)
    t1 = add64(h + s1 + chValue + k, wt)

    calculateWorkers(
      messageSchedule,
      workers,
      [add64(t1, t2), a, b, c, add64(d, t1), e, f, g],
      t + 1
    )
  end

  @spec calculateIntermediateHashValue(list(integer), list(integer())) :: list(integer())
  def calculateIntermediateHashValue(workers, hashValues) do
    Enum.map(
      List.zip([hashValues, workers]),
      fn {hashValue, worker} ->
        add64(hashValue, worker)
      end
    )
  end

  @spec calculateMessageSchedule(list(binary())) :: list(integer())
  def calculateMessageSchedule(messageBlock) do
    calculateMessageSchedule(messageBlock, [], 1)
  end

  @spec calculateMessageSchedule(list(binary()), list(binary()), integer()) :: list(integer())
  def calculateMessageSchedule(_, w, 81) do
    binaryListToBinary(w)
  end

  def calculateMessageSchedule(messageBlock, _, _) do
    extend(binaryListToBinary(messageBlock), 16)
  end

  @spec binaryListToBinary(list(binary)) :: binary()
  def binaryListToBinary(messageBlock) do
    List.foldl(
      messageBlock,
      <<>>,
      fn(binary, result) ->
        concatBinary(result, binary)
      end
    )
  end

  @spec concatBinary(binary(), binary()) :: binary()
  def concatBinary(bin1, bin2) do
    <<bin1 :: binary, bin2 :: binary>>
  end

  def extend(messageSchedule, 80) do
    messageSchedule
  end

  def extend(messageSchedule, t) do
    w2 = getWordFromByteOffset(messageSchedule, t - 2)
    w7 = getWordFromByteOffset(messageSchedule, t - 7)
    w15 = getWordFromByteOffset(messageSchedule, t - 15)
    w16 = getWordFromByteOffset(messageSchedule, t - 16)
    s0 = sigma0(w15)
    s1 = sigma1(w2)
    next = add64(w16 + s0 + w7, s1)
    extend(concatBinary(messageSchedule, <<next :: size(64)>>), t + 1)
  end

  @spec add64(integer(), integer()) :: integer()
  def add64(x, y) do
    band(x + y, 0xFFFFFFFFFFFFFFFF)
  end

  @spec getWordFromByteOffset(binary(), integer()) :: integer()
  def getWordFromByteOffset(binary, byteOffset) do
    getBitsFromByteOffset(binary, byteOffset, 64)
  end

  @spec getBitsFromByteOffset(binary(), integer(), integer()) :: integer()
  def getBitsFromByteOffset(binary, byteOffset, numberOfBits) do
    getBitsFromOffset(binary, byteOffset * 8, numberOfBits)
  end

  @spec getBitsFromOffset(binary(), integer(), integer()) :: integer()
  def getBitsFromOffset(binary, offset, numberOfBits) do
    <<_ :: binary - size(offset), result :: size(numberOfBits), _ :: binary>> = binary
    result
  end

  def rotateRight(word, count) do
    rest = 64 - count
    <<top :: size(rest), bottom :: size(count)>> = <<word :: size(64)>>
    <<new :: size(64)>> = <<bottom :: size(count), top :: size(rest)>>
    new
  end

  @spec shiftRight(binary(), integer()) :: binary()
  def shiftRight(wordToShift, shiftAmount) do
    bsr(wordToShift, shiftAmount)
  end

  @spec ch(integer(), integer(), integer()) :: integer()
  def ch(x, y, z) do
    band(x, y)
    |> bxor(
         bnot(x)
         |> band(z)
       )
  end

  @spec maj(integer(), integer(), integer()) :: integer()
  def maj(x, y, z) do
    band(x, y)
    |> bxor(band(x, z))
    |> bxor(band(y, z))
  end

  @spec sum0(integer()) :: integer()
  def sum0(y) do
    rotateRight(y, 28)
    |> bxor(rotateRight(y, 34))
    |> bxor(rotateRight(y, 39))
  end

  @spec sum1(integer()) :: integer()
  def sum1(y) do
    rotateRight(y, 14)
    |> bxor(rotateRight(y, 18))
    |> bxor(rotateRight(y, 41))
  end

  @spec sigma0(integer()) :: integer()
  def sigma0(y) do
    rotateRight(y, 1)
    |> bxor(rotateRight(y, 8))
    |> bxor(shiftRight(y, 7))
  end

  @spec sigma1(integer()) :: integer()
  def sigma1(y) do
    rotateRight(y, 19)
    |> bxor(rotateRight(y, 61))
    |> bxor(shiftRight(y, 6))
  end

  @spec preprocess(binary()) :: list(list(binary()))
  def preprocess(<<message :: binary>>) do
        message
        |> padd
        |> parse
  end

  @spec parse(binary()) :: list(list(binary()))
  def parse(<<paddedMessage :: binary>>) do
    for(x <- splitToNByteBlocks(paddedMessage, 128), do: splitToNByteBlocks(x, 8))
  end

  @spec splitToNByteBlocks(binary(), integer()) :: list(binary())
  def splitToNByteBlocks(<<bin :: binary>>, numberOfBytes) do
    Enum.reverse(splitToNByteBlocksInternal(bin, numberOfBytes, []))
  end

  @spec splitToNByteBlocksInternal(binary(), integer(), list(binary())) :: list(binary())
  def splitToNByteBlocksInternal(<<bin :: binary>>, numberOfBytes, acc)
      when byte_size(bin) <= numberOfBytes do
    [bin | acc]
  end
  def splitToNByteBlocksInternal(bin, numberOfBytes, acc) do
    <<part :: binary - size(numberOfBytes), rest :: binary>> = bin
    splitToNByteBlocksInternal(rest, numberOfBytes, [part | acc])
  end

  @spec padd(binary()) :: binary()
  def padd(<<messageToPadd :: binary>>) do
    messageLength = bit_size(messageToPadd)

    addBit(messageToPadd)
    |> paddZeroes(messageLength)
    |> lengthPad(messageLength)
  end

  @spec addBit(bitstring()) :: bitstring()
  def addBit(<<messageToAppend :: bitstring>>) do
    <<messageToAppend :: bitstring, <<1 :: size(1)>> :: bitstring>>
  end

  # Adds the zeroes until the bitstring is 896 bits
  @spec paddZeroes(bitstring(), integer()) :: bitstring()
  def paddZeroes(<<unPaddedMessage :: bitstring>>, messageLength) do
    numberOfZeroes = numberOfZeroesToAdd(messageLength)
    <<unPaddedMessage :: bitstring, <<0 :: size(numberOfZeroes)>> :: bitstring>>
  end

  # Calculates the number of zeroes to pad until the message pre-length padded is 896
  @spec numberOfZeroesToAdd(integer()) :: integer()
  def numberOfZeroesToAdd(messageLength) do
    # 896 magic constant from chapter 5.1.2, + 1 because message is padded with a bit
    mod(896 - (messageLength + 1), 1024)
  end

  # Adds the 128 bit block that is all zeroes until the message length makes it fit
  @spec lengthPad(bitstring(), integer()) :: bitstring()
  def lengthPad(<<zeroPaddedMessage :: bitstring>>, messageLength) do
    <<zeroPaddedMessage :: bitstring, <<messageLength :: 128>> :: bitstring>>
  end

  @spec mod(integer(), integer()) :: integer()
  def mod(x, y) when x > 0 do
    rem(x, y)
  end

  def mod(x, y) when x < 0 do
    rem(y + x, y)
  end

  def mod(0, _) do
    0
  end

  @spec initialWorkers :: list(integer())
  def initialWorkers() do
    [
      0x6A09E667F3BCC908,
      0xBB67AE8584CAA73B,
      0x3C6EF372FE94F82B,
      0xA54FF53A5F1D36F1,
      0x510E527FADE682D1,
      0x9B05688C2B3E6C1F,
      0x1F83D9ABFB41BD6B,
      0x5BE0CD19137E2179
    ]
  end

  @spec kConstants :: binary()
  def kConstants() do
    <<
      0x428A2F98D728AE22 :: 64,
      0x7137449123EF65CD :: 64,
      0xB5C0FBCFEC4D3B2F :: 64,
      0xE9B5DBA58189DBBC :: 64,
      0x3956C25BF348B538 :: 64,
      0x59F111F1B605D019 :: 64,
      0x923F82A4AF194F9B :: 64,
      0xAB1C5ED5DA6D8118 :: 64,
      0xD807AA98A3030242 :: 64,
      0x12835B0145706FBE :: 64,
      0x243185BE4EE4B28C :: 64,
      0x550C7DC3D5FFB4E2 :: 64,
      0x72BE5D74F27B896F :: 64,
      0x80DEB1FE3B1696B1 :: 64,
      0x9BDC06A725C71235 :: 64,
      0xC19BF174CF692694 :: 64,
      0xE49B69C19EF14AD2 :: 64,
      0xEFBE4786384F25E3 :: 64,
      0x0FC19DC68B8CD5B5 :: 64,
      0x240CA1CC77AC9C65 :: 64,
      0x2DE92C6F592B0275 :: 64,
      0x4A7484AA6EA6E483 :: 64,
      0x5CB0A9DCBD41FBD4 :: 64,
      0x76F988DA831153B5 :: 64,
      0x983E5152EE66DFAB :: 64,
      0xA831C66D2DB43210 :: 64,
      0xB00327C898FB213F :: 64,
      0xBF597FC7BEEF0EE4 :: 64,
      0xC6E00BF33DA88FC2 :: 64,
      0xD5A79147930AA725 :: 64,
      0x06CA6351E003826F :: 64,
      0x142929670A0E6E70 :: 64,
      0x27B70A8546D22FFC :: 64,
      0x2E1B21385C26C926 :: 64,
      0x4D2C6DFC5AC42AED :: 64,
      0x53380D139D95B3DF :: 64,
      0x650A73548BAF63DE :: 64,
      0x766A0ABB3C77B2A8 :: 64,
      0x81C2C92E47EDAEE6 :: 64,
      0x92722C851482353B :: 64,
      0xA2BFE8A14CF10364 :: 64,
      0xA81A664BBC423001 :: 64,
      0xC24B8B70D0F89791 :: 64,
      0xC76C51A30654BE30 :: 64,
      0xD192E819D6EF5218 :: 64,
      0xD69906245565A910 :: 64,
      0xF40E35855771202A :: 64,
      0x106AA07032BBD1B8 :: 64,
      0x19A4C116B8D2D0C8 :: 64,
      0x1E376C085141AB53 :: 64,
      0x2748774CDF8EEB99 :: 64,
      0x34B0BCB5E19B48A8 :: 64,
      0x391C0CB3C5C95A63 :: 64,
      0x4ED8AA4AE3418ACB :: 64,
      0x5B9CCA4F7763E373 :: 64,
      0x682E6FF3D6B2B8A3 :: 64,
      0x748F82EE5DEFB2FC :: 64,
      0x78A5636F43172F60 :: 64,
      0x84C87814A1F0AB72 :: 64,
      0x8CC702081A6439EC :: 64,
      0x90BEFFFA23631E28 :: 64,
      0xA4506CEBDE82BDE9 :: 64,
      0xBEF9A3F7B2C67915 :: 64,
      0xC67178F2E372532B :: 64,
      0xCA273ECEEA26619C :: 64,
      0xD186B8C721C0C207 :: 64,
      0xEADA7DD6CDE0EB1E :: 64,
      0xF57D4F7FEE6ED178 :: 64,
      0x06F067AA72176FBA :: 64,
      0x0A637DC5A2C898A6 :: 64,
      0x113F9804BEF90DAE :: 64,
      0x1B710B35131C471B :: 64,
      0x28DB77F523047D84 :: 64,
      0x32CAAB7B40C72493 :: 64,
      0x3C9EBE0A15C9BEBC :: 64,
      0x431D67C49C100D4C :: 64,
      0x4CC5D4BECB3E42B6 :: 64,
      0x597F299CFC657E2A :: 64,
      0x5FCB6FAB3AD6FAEC :: 64,
      0x6C44198C4A475817 :: 64
    >>
  end
end
