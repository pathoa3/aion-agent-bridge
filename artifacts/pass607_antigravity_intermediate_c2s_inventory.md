# Pass607 Antigravity Intermediate C2S Inventory

We mapped all intermediate C2S data packets sent between the lobby handshake (`Pkt # 7522`) and the first chat packet (`Pkt # 8745`).

## 1. Inventory Summary Table
All raw packet payloads are redacted to protect data integrity and conform to security rules.

| Packet No | Direction | Length (Bytes) | SHA256 Hash of Payload | Relative Index | Phase |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 7526 | C2S | 24 | d4e0daf39ea086b3eccc081c8aef72468d398bb595db81b5bb3d3831d8912c83 | 1 | lobby_phase |
| 7528 | C2S | 11 | 8281388d91f43f1f87096971234c55ea63b0fe2abfa6d0edaeaa7e8bb119c043 | 2 | lobby_phase |
| 7538 | C2S | 31 | e23924900cb5804284f5eb8bdd74e9015a15c4f8c2f4ba73360e1ee4e69aec42 | 3 | lobby_phase |
| 7540 | C2S | 72 | 4430197a813d045c3b0025e121c028110f7f79c96f782a4c373326af000d5044 | 4 | lobby_phase |
| 7545 | C2S | 11 | 02318d8ae506c1e4befdad4a9fab8a12c89a00523d46a8119e4f6db8a8bf5597 | 5 | lobby_phase |
| 7554 | C2S | 9 | 5d17df448b9b7e659bdb5c8fc3f7726c9823e729a09525fa0b03146e3dca922e | 6 | lobby_phase |
| 7583 | C2S | 7 | 1c1df100d1c557adfa4b96e5d8400a476d5c10642df63efb5f9463bdf9478d1f | 7 | lobby_phase |
| 7586 | C2S | 11 | 81b44ed8f7ecb010cb2e99ca15c7c1ecbb78fdd591502b4e7de15d0abf1c94bb | 8 | lobby_phase |
| 7646 | C2S | 7 | 1301e826313d19f96427557c2e1c720768d90bfddc68e038474bbff7c28ff1c3 | 9 | lobby_phase |
| 7759 | C2S | 8 | 27932ef9d1a3609b8606515f4625de387a302cb6b7ecbebf76901c3e01960959 | 10 | lobby_phase |
| 7761 | C2S | 15 | a16ef9d105b1fec88900fc52f08fa9800c7559e475574ecb72f27e0a95342d9a | 11 | lobby_phase |
| 7779 | C2S | 11 | b902725eae850c9e11d2c466744218d7e0326df7a1dd907912a2faced57c95fe | 12 | lobby_phase |
| 7781 | C2S | 22 | d97bf71a11ef173c50aa9c2cd75fb4e447991b5cae4703faeda0853a4d55d4de | 13 | lobby_phase |
| 7786 | C2S | 7 | ad9fc1f1a3621792bcef0de54f62524aae04fd33f44edb1af2ce85f9d935499b | 14 | lobby_phase |
| 7789 | C2S | 7 | 10b9cebfe6c6b36e9be6615111489e420dc397e7114d611ebe0449e53f048c2b | 15 | lobby_phase |
| 7810 | C2S | 8 | b73b0dfe1e650f61d7e90a56f41aee4684a157cfe41c12081fe996ddf3611598 | 16 | lobby_phase |
| 7814 | C2S | 11 | 4f29b5a766d98d74505ed4c2097aefaab07da997946d6808b8c48cfe5e6cca7b | 17 | lobby_phase |
| 7833 | C2S | 21 | e0c9b7dca4554fa04d173a779727917770a3d5bfb6de77d553425cbae0036942 | 18 | lobby_phase |
| 7837 | C2S | 17 | b4667396d457acd29dcac125e961313860d8f81889e2af1a6aa96b9a7ef43e63 | 19 | lobby_phase |
| 7841 | C2S | 21 | 6592606cf1e1f2490a7e01d730871bd39d99c76edf905140cb464505266aaa5d | 20 | lobby_phase |
| 7853 | C2S | 11 | 7dabb2ddc54aff6854b84985b71ec064b10ea6237ab806d3e32a575df10fe999 | 21 | lobby_phase |
| 7866 | C2S | 11 | 9a70364b0b7d022fe9988aabea26b5cc77e087f0e227eafe45421b3287b32b68 | 22 | lobby_phase |
| 7869 | C2S | 12 | 5c5a0f0202f6f946d6c528c7f6870b8224ea403d2dec735f9b5c93efc7de5c97 | 23 | lobby_phase |
| 7874 | C2S | 33 | a8f5a3a04895287f2158b0eae1c1e3974e8c7e4a5e09c3d978ec0e6076d8b7b3 | 24 | lobby_phase |
| 7876 | C2S | 21 | f2535fc52b37ae6027ff8d72609590ff9c05d3c01722d21d8e74b41d243a5706 | 25 | lobby_phase |
| 7882 | C2S | 11 | 857174a5bc6e7b4feb8dfcfdde1b669df3c70a1c19e0e41bdd4573e6861ccbeb | 26 | lobby_phase |
| 7974 | C2S | 5060 | e52cde97abea6e09633e32f3abb46622e8630522429dbc5de549b6530b3c2b1f | 27 | lobby_phase |
| 8055 | C2S | 11 | c0e496329bf62bfa4d8b2005271944306d1969844e8d0a4ffe6f0ee69f1efad8 | 28 | lobby_phase |
| 8255 | C2S | 11 | ac77efc5480ac5319a1ec6eb655a32c80dd083bbd2c290e3034ab1f591c49fea | 29 | lobby_phase |
| 8641 | C2S | 11 | a4ebd2c9847b8ccfcf3fe33d39834a6658c2e4886d000c9c466c5ca6bfd993fc | 30 | lobby_phase |
| 8733 | C2S | 11 | 00073cd4d062a48f49336956ea461ae6bb907924298a442cf0c50face4c13b2a | 31 | lobby_phase |

## 2. Conclusion
The running key state of the C2S connection was mutated exactly 31 times before the first chat message (`Pkt # 8745`) was transmitted. Direct decryption using the base key derived from `Pkt # 7522` is therefore expected to fail without simulating these intermediate state updates.
