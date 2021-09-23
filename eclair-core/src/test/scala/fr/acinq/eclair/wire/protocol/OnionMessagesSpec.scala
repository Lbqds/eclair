/*
 * Copyright 2021 ACINQ SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.acinq.eclair.wire.protocol

import fr.acinq.bitcoin.Crypto.{PrivateKey, PublicKey}
import fr.acinq.bitcoin.{ByteVector32, Crypto}
import fr.acinq.eclair.crypto.Sphinx
import org.scalatest.funsuite.AnyFunSuite
import scodec.bits.{ByteVector, HexStringSyntax}
import scodec.{Attempt, DecodeResult}

import scala.util.{Failure, Success}

/**
 * Created by thomash on 23/09/2021.
 */

class OnionMessagesSpec extends AnyFunSuite {

  test("Simple enctlv for Alice, next is Bob") {
    val nodePrivateKey = PrivateKey(hex"414141414141414141414141414141414141414141414141414141414141414101")
    val nodeId = PublicKey(hex"02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619")
    assert(nodePrivateKey.publicKey == nodeId)
    val blindingSecret = PrivateKey(hex"050505050505050505050505050505050505050505050505050505050505050501")
    val blindingKey = PublicKey(hex"0362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7")
    assert(blindingSecret.publicKey == blindingKey)
    val sharedSecret = ByteVector32(hex"2e83e9bc7821d3f6cec7301fa8493aee407557624fb5745bede9084852430e3f")
    assert(Sphinx.computeSharedSecret(nodeId, blindingSecret) == sharedSecret)
    assert(Sphinx.computeSharedSecret(blindingKey, nodePrivateKey) == sharedSecret)
    assert(Sphinx.mac(ByteVector("blinded_node_id".getBytes), sharedSecret) == ByteVector32(hex"7d846b3445621d49a665e5698c52141e9dda8fa2fe0c3da7e0f9008ccc588a38"))
    val blindedNodeId = PublicKey(hex"02004b5662061e9db495a6ad112b6c4eba228a079e8e304d9df50d61043acbc014")
    val nextNodeId = PublicKey(hex"0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c")
    val encmsg = hex"04210324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c"
    val Sphinx.RouteBlinding.BlindedRoute(_, blindedHops) = Sphinx.RouteBlinding.create(blindingSecret, nodeId :: Nil, encmsg :: Nil)
    assert(blindedHops.head.blindedPublicKey == blindedNodeId)
    assert(Crypto.sha256(blindingKey.value ++ sharedSecret.bytes) == ByteVector32(hex"bae3d9ea2b06efd1b7b9b49b6cdcaad0e789474a6939ffa54ff5ec9224d5b76c"))
    val enctlv = hex"6970e870b473ddbc27e3098bfa45bb1aa54f1f637f803d957e6271d8ffeba89da2665d62123763d9b634e30714144a1c165ac9"
    assert(blindedHops.head.encryptedPayload == enctlv)
    OnionCodecs.messageRelayNextCodec.decode(encmsg.bits) match {
      case Attempt.Successful(DecodeResult(relayNext, _)) =>
        assert(relayNext.nextNodeId == nextNodeId)
        assert(relayNext.nextBlinding.isEmpty)
      case Attempt.Failure(err) => fail(err.toString)
    }
    Sphinx.RouteBlinding.decryptPayload(nodePrivateKey, blindingKey, enctlv) match {
      case Success((decrypted, _)) => assert(decrypted == encmsg)
      case Failure(err) => fail(err.toString)
    }
  }

  test("Blinding-key-override enctlv for Bob, next is Carol") {
    val nodePrivateKey = PrivateKey(hex"424242424242424242424242424242424242424242424242424242424242424201")
    val nodeId = PublicKey(hex"0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c")
    assert(nodePrivateKey.publicKey == nodeId)
    val blindingSecret = PrivateKey(hex"76d4de6c329c79623842dcf8f8eaee90c9742df1b5231f5350df4a231d16ebcf01")
    val blindingKey = PublicKey(hex"03fc5e56da97b462744c9a6b0ba9d5b3ffbfb1a08367af9cc6ea5ae03c79a78eec")
    assert(blindingSecret.publicKey == blindingKey)
    val sharedSecret = ByteVector32(hex"f18a1ddb1cb27d8fc4faf2cf317e87524fcc6b7f053496d95bf6e6809d09851e")
    assert(Sphinx.computeSharedSecret(nodeId, blindingSecret) == sharedSecret)
    assert(Sphinx.computeSharedSecret(blindingKey, nodePrivateKey) == sharedSecret)
    assert(Sphinx.mac(ByteVector("blinded_node_id".getBytes), sharedSecret) == ByteVector32(hex"8074773a3745818b0d97dd875023486cc35e7afd95f5e9ec1363f517979e8373"))
    val blindedNodeId = PublicKey(hex"026ea8e36f78e038c659beba9229699796127471d9c7a24a0308533371fd63ad48")
    val nextNodeId = PublicKey(hex"027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007")
    val encmsg = hex"0421027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa20070c2102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f"
    val Sphinx.RouteBlinding.BlindedRoute(_, blindedHops) = Sphinx.RouteBlinding.create(blindingSecret, nodeId :: Nil, encmsg :: Nil)
    assert(blindedHops.head.blindedPublicKey == blindedNodeId)
    assert(Crypto.sha256(blindingKey.value ++ sharedSecret.bytes) == ByteVector32(hex"9afb8b2ebc174dcf9e270be24771da7796542398d29d4ff6a4e7b6b4b9205cfe"))
    val enctlv = hex"1630da85e8759b8f3b94d74a539c6f0d870a87cf03d4986175865a2985553c997b560c36613bd9184c1a6d41a37027aabdab5433009d8409a1b638eb90373778a05716af2c215b3d31db7b2c2659716e663ba3d9c909"
    assert(blindedHops.head.encryptedPayload == enctlv)
    OnionCodecs.messageRelayNextCodec.decode(encmsg.bits) match {
      case Attempt.Successful(DecodeResult(relayNext, _)) =>
        assert(relayNext.nextNodeId == nextNodeId)
        assert(relayNext.nextBlinding contains PrivateKey(hex"070707070707070707070707070707070707070707070707070707070707070701").publicKey)
      case Attempt.Failure(err) => fail(err.toString)
    }
    Sphinx.RouteBlinding.decryptPayload(nodePrivateKey, blindingKey, enctlv) match {
      case Success((decrypted, _)) => assert(decrypted == encmsg)
      case Failure(err) => fail(err.toString)
    }
  }

  test("Padded enctlv for Carol, next is Dave") {
    val nodePrivateKey = PrivateKey(hex"434343434343434343434343434343434343434343434343434343434343434301")
    val nodeId = PublicKey(hex"027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007")
    assert(nodePrivateKey.publicKey == nodeId)
    val blindingSecret = PrivateKey(hex"070707070707070707070707070707070707070707070707070707070707070701")
    val blindingKey = PublicKey(hex"02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f")
    assert(blindingSecret.publicKey == blindingKey)
    val sharedSecret = ByteVector32(hex"8c0f7716da996c4913d720dbf691b559a4945bf70cdd18e0b61e3e42635efc9c")
    assert(Sphinx.computeSharedSecret(nodeId, blindingSecret) == sharedSecret)
    assert(Sphinx.computeSharedSecret(blindingKey, nodePrivateKey) == sharedSecret)
    assert(Sphinx.mac(ByteVector("blinded_node_id".getBytes), sharedSecret) == ByteVector32(hex"02afb2187075c8af51488242194b44c02624785ccd6fd43b5796c68f3025bf88"))
    val blindedNodeId = PublicKey(hex"02f4f524562868a09d5f54fb956ade3fa51ef071d64d923e395cc6db5e290ec67b")
    val nextNodeId = PublicKey(hex"032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991")
    val encmsg = hex"012300000000000000000000000000000000000000000000000000000000000000000000000421032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991"
    val Sphinx.RouteBlinding.BlindedRoute(_, blindedHops) = Sphinx.RouteBlinding.create(blindingSecret, nodeId :: Nil, encmsg :: Nil)
    assert(blindedHops.head.blindedPublicKey == blindedNodeId)
    assert(Crypto.sha256(blindingKey.value ++ sharedSecret.bytes) == ByteVector32(hex"cc3b918cda6b1b049bdbe469c4dd952935e7c1518dd9c7ed0cd2cd5bc2742b82"))
    val enctlv = hex"8285acbceb37dfb38b877a888900539be656233cd74a55c55344fb068f9d8da365340d21db96fb41b76123207daeafdfb1f571e3fea07a22e10da35f03109a0380b3c69fcbed9c698086671809658761cf65ecbc3c07a2e5"
    assert(blindedHops.head.encryptedPayload == enctlv)
    OnionCodecs.messageRelayNextCodec.decode(encmsg.bits) match {
      case Attempt.Successful(DecodeResult(relayNext, _)) =>
        assert(relayNext.nextNodeId == nextNodeId)
        assert(relayNext.nextBlinding.isEmpty)
      case Attempt.Failure(err) => fail(err.toString)
    }
    Sphinx.RouteBlinding.decryptPayload(nodePrivateKey, blindingKey, enctlv) match {
      case Success((decrypted, _)) => assert(decrypted == encmsg)
      case Failure(err) => fail(err.toString)
    }
  }
}
