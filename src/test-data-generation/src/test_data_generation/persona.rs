// Copyright (C) Microsoft Corporation. All rights reserved.

//#![cfg_attr(rustfmt, rustfmt_skip)]
#![deny(clippy::expect_used)]
#![deny(clippy::manual_assert)]
#![deny(clippy::panic)]
#![deny(clippy::unwrap_used)]
#![deny(elided_lifetimes_in_paths)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::type_complexity)]
#![allow(clippy::empty_line_after_doc_comments)] //? TODO: Remove temp development code
#![allow(clippy::let_and_return)] //? TODO: Remove temp development code
#![allow(clippy::needless_lifetimes)] //? TODO: Remove temp development code
#![allow(dead_code)] //? TODO: Remove temp development code
#![allow(unused_assignments)] //? TODO: Remove temp development code
#![allow(unused_braces)] //? TODO: Remove temp development code
#![allow(unused_imports)] //? TODO: Remove temp development code
#![allow(unused_mut)] //? TODO: Remove temp development code
#![allow(unused_variables)] //? TODO: Remove temp development code
#![allow(unreachable_code)] //? TODO: Remove temp development code
#![allow(non_camel_case_types)] //? TODO: Remove temp development code
#![allow(non_snake_case)] //? TODO: Remove temp development code
#![allow(non_upper_case_globals)] //? TODO: Remove temp development code
#![allow(noop_method_call)] //? TODO: Remove temp development code

#[rustfmt::skip] //? TODO: Remove temp development code
use std::{
    borrow::Cow,
    //cell::RefCell,
    //collections::{BTreeSet, BTreeMap},
    //collections::{HashSet, HashMap},
    //hash::{BuildHasher, Hash, Hasher},
    //io::{BufRead, Cursor},
    //iter::zip,
    marker::PhantomData,
    //path::{Path, PathBuf},
    //process::ExitCode,
    //rc::Rc,
    //str::FromStr,
    sync::{
        Arc,
        LazyLock,
    },
};

use const_default::ConstDefault;
//use anyhow::{anyhow, bail, ensure, Context, Result};
//use either::Either;
use fnv::FnvHasher;
//use futures_lite::future::{self, FutureExt};
//use hashbrown::HashMap;
use indoc::indoc;
//use rand::{distr::Uniform, Rng, RngCore};
//use serde::{Deserialize, Serialize};
use static_assertions::{const_assert, const_assert_eq}; // {assert_obj_safe, assert_impl_all, assert_cfg}
//use tracing::{debug, error, field::display as trace_display, info, info_span, instrument, trace, trace_span, warn};
//use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::test_data_generation::*;

//=================================================================================================|

const FIRST_NAMES_CNT_L2: u8 = 7;
const FIRST_NAMES_CNT: usize = 1 << FIRST_NAMES_CNT_L2;
static FIRST_NAMES: LazyLock<Box<[&str]>> = LazyLock::new(|| {
    /*
    // First/given names exactly as proposed by generative AI:
    const S: &str = indoc! {"
        Adrián Ælíårá Áëllørá Ælødië Æmílîånä Ænôrä Álârýssà Älëstrå Aléxiøs Älkýøn
        𝔄mëlyn Anástasia 𝔄stráël Âstrïd 𝔄thëldør Åuréliå 𝔄urélius Âvérýllë Bëátřïx
        Bërnard Brýnjär Çælestïn Cælíus Cässandra Cécilia Célíndrå Cláudia Cørdéllíá
        Cørynë Dáëdrïc 𝔇æmión Dämìán Dårçýné 𝔇aríenne Dêlphïníá Dømíník Dréamïs 𝔇rëavyn
        Édwýn Èlena Ëlivændër Élodíë Elysêa Èmeline Émeric Ëmmànuél Érvýn Ésméráldus
        Fáëlíæn Fïørá Gavriel Gídéøn Hælïøs Hæthérïà Hållëýrë Hêlëna Ígåcíø Ìgnatius
        Isabël Íshtâr Jãrhëd Jásmïnæ Jørdán Kæssánder Kýræl Léándrâ 𝔏éontýn Lïliana
        Lórenzo 𝔏øríenna Łúcïän Lúciáñä 𝔏ücién Lúcio Lúmíra Lúthøriø 𝔏ysändra Lýsåndré
        Mærïkh Mãláchï Máriana Mélykîér Mïchael Mýríäd Nævá Nikólai Nýmæ Nýxándër Océane
        Ócëanø Óliver Ølíviêr Ølýndà Órëllïüs Øríøndér Pérynéllë Qüintën Qüíntëssá
        Rãfael Ràffíël Rågnär Ráînnæ Ráphaëlle Rûnëløch Sãpphýrra Sébastien Séphíróth
        Séraphina Séraphine 𝔖eraphíne Sëréníty Sévérïn Sévríná Sølånýâ 𝔖olëní Šøren
        𝔖tärcæl Štêfánïø 𝔖ylvæn Sylvérïn Thëåndër Théödör Théodoric Théódøric Tímæüs
        Týræn Tŷränníá Týrønë Ûrëlíüš Ûrsúla Vællôrå Vælyrïå Véspériâ Vîçtörïø Vïktoría
        Víllým Vivîenne Xáñthíppë Xãnthøús Zåríéllë Záýlïn Zénøvîä Zéphýrå Zéphýríne
        Zyphíra 𐌰lysiå 𐌰ndrøméda 𐌰zúriél 𐌹llýriå 𐌹nárion 𐌹saríön 𐍂æfnær 𐍂aelynn 𐍂unevér
        𐍃everïn 𐍃ólanthe 𐍃ýlvía 𐍈ylánder 𐍈ystérian 𐍈yväel
    "};
    // */

    // First/given names proposed by generative AI, lightly curated:
    const S: &str = indoc! {"
        Ælíårá Ælødië Æmílîånä Ænôrä Álârýssà Älëstrå Aléxiøs Älkýøn 𝔄stráël Âstrïd
        𝔄thëldør Åuréliå 𝔄urélius Âvérýllë Bëátřïx Brýnjär Çælestïn Cælíus Cässandra
        Célíndrå Cørdéllíá Cørynë Dáëdrïc 𝔇æmión Dårçýné 𝔇aríenne Dêlphïníá Dréamïs
        𝔇rëavyn Édwýn Ëlivændër Élodíë Elysêa Èmeline Émeric Érvýn Ésméráldus Fáëlíæn
        Fïørá Gavriel Gídéøn Hælïøs Hæthérïà Ígåcíø Ìgnatius Íshtâr Jãrhëd Jásmïnæ
        Kæßánder Kýræl Léándrâ 𝔏éontýn 𝔏øríenna Łúcïän Lúciáñä Lúmíra Lúthøriø 𝔏ysändra
        Lýsåndré Mærïkh Mãláchï Máriana Mélykîér Mýríäd Nikólai Nýmæ Nýxándër Océane
        Ócëanø Ølýndà Órëllïüs Øríøndér Qüintën Qüíntëßá Ràffíël Rågnär Ráînnæ Ráphaëlle
        Rûnëløch Sãpphýrra 𝔖eraphíne Sërénítγ Sévríná Sølånýâ 𝔖olëní ẞrýnjär 𝔖tärcæl
        Starshard Štêfánïø 𝔖ylvæn Sylvérïn Sγlvérïn S𐍈lånýâ Thëåndër Théödör Théódøric
        Tímæüs Tŷränníá Týrønë Ûrëlíüš Ûrsúla Vælyrïå Véspériâ Vîçtörïø Vïktoría Víllým
        Xáñthíppë Xãnthøús Zåríéllë Záýlïn Zéphýrå Zéphýríne Zγphíra 𐌰lysiå 𐌰ndrøméda
        𐌰zúriél 𐌹llýriå 𐌹nárion 𐍂æfnær 𐍂aelγnn 𐍂unevér 𐍃everïn 𐍃ólanthe 𐍃ýlvía 𐍈ylánder
        𐍈ystérian 𐍈yväel 𐍈γlánder
    "};

    let strs = S.split_whitespace().map(str::trim).collect::<Box<[&str]>>();
    assert_eq!(strs.len(), FIRST_NAMES_CNT);
    strs
});

const LAST_NAMES_CNT_L2: u8 = 7;
const LAST_NAMES_CNT: usize = 1 << LAST_NAMES_CNT_L2;
static LAST_NAMES: LazyLock<Box<[&str]>> = LazyLock::new(|| {
    /*
    // Last/family names exactly as proposed by generative AI:
    const S: &str = indoc! {"
        Ætherclåw Ætherweaver 𝔄lchëmýst Âlmïght Ámbërståg 𝔄mbërwýn 𝔄rchëwïnd 𝔄shënhåll
        Áshmøørë Áürørè Blåçkswørd Bládëwyn Blúmêmåntle Bóokwhisper Cælëstrîa
        Crystálgaze Dårkskäle 𝔇ärkspýrë Dårkswáń 𝔇rækwøld Ðrágømïre Drágønfåll Drákmïre
        Düstmøøn 𝔇uststrøm Dûstwøvën Ébbënfløw Ébønstryke Ëlementalstrider Élèvéńfåll
        Émbërçråft Embergrâce Ëvérshadé Færęsláyër Fåérýwíng Fåethérhêlm Fårélïght
        Fårélíght Fírêcrøst Fîrestone Fîrëstrøm Fläshwýnd Frøstlûmë Fýrëswørn Gälëstrîde
        Gearsøul Gläçíørè Glædestöne Glîmmerwillow Glýmmerstøkë Gøldenbøugh Gòldënláçe
        Gølðénrûnë Hëllêbørë Høpebløøm Ícëmýst Inkdrifter Ínvërnessë Írisflåme Kýnbládë
        Léafsinger 𝔏øchfåll 𝔏ørestår Lùmenwing 𝔏úmëstøne Lümínøvå Lünårbøùnd Lúnárglãdé
        Lúnåwhîspér 𝔏ünëmïst Lýghtføøt Månesworn Månífæst Møonblǿssøm Møønbørñ Moonrîse
        Møønsøng Mòønstrïdé Mørníngstårr Mýstëbrøkë Nébülëgård Níghtstrŷdër Níghtswørd
        Nightwíng Nøváspýrë Øåkbóûgh Rávenskyë Rîvërsông Rúnecrest Rúnefrøst Rûnësprïng
        Rünëwéavër Sægebrŷght Séphýrøs 𝔖ëraphfýr Shadowbinder 𝔖hadowbørn Shådøwbríght
        Shådøwmïst Sîlvérblâde Sílverbolt Sílvercrëst Sílverløck Sírrøwýnd 𝔖kyfæll
        Skýførtë Skytöuch Sølárís Sólènsýng Sôlstícê Sôulstëppë Stardüst Stårflåmë
        Starglýmmer Stårrfølk Stårryng Stårshådë Starshard Stëamheart Stëllåfýrë
        𝔖tormbrŷght Størmflýght Stórmforge Sūnshådøw Sùnshard Sûnstønë Swíftwålkër
        Tæmbërflåre Tëmplëflãmë Thørńblåde Thørnëdräke Thûndërhëärt Thunderstrîde
        Tidecaller Tímëstrøm Tîmèwŷsè Týrsdóttir Vǽlkŷrësøn Væylsháðë Vålpïne Wîldheart
        Wîndwhisper Wíndwhîsper Wýldewísp Wýńdspïrït 𐌰lýrïsøng 𐌰ndræsyl 𐌰strånøvå 𐌹cëmïr
        𐌹llümíøn 𐌹nfërnwynd 𐍂ävënswørd 𐍂øthmýr 𐍂ünehårð 𐍃hädeførge 𐍃kýbrêäkër 𐍃ølvést
        𐍈ælestørm 𐍈álkýr 𐍈ørënblåde
    "};
    // */

    // Last/family names proposed by generative AI, lightly curated:
    const S: &str = indoc! {"
        Ætherclåw Ætherweaver 𝔄lchëmýst Âlmïght 𝔄mbërwýn 𝔄rchëwïnd 𝔄shënhåll Áshmøørë
        Áürørè Blåçkswørd Bládëwyn Blúmêmåntle Cælëstrîa Crystálgaze 𝔇ärkspýrë Dårkswáń
        𝔇rækwøld Ðrágømïre Drágønfåll 𝔇üstmoon Dûstwøvën Ébbënfløw Ébønstryke Élvéńfåll
        Émbërçråft Embergrâce Ëvérshadé Færęsláγër Fåérýwíng Fårélïght Fîrëstrøm
        Fläshwýnd Frøstrune Fýrëswørn Gälëstrîde Gläçíørè Glædestöne Glýmmerstøkë
        Gøldenbøugh Gòldënláçe Hëllêbørë Høpebløøm Ícëmýst Ínvërneßë Írisflåme Kýnbládë
        Léafsinger 𝔏øchfåll 𝔏ørestår Lùmenwing 𝔏úmëstøne Lümínøvå Lúnárglãdé Lúnåwhîspér
        𝔏ünëmïst Lýghtføøt Månífæst Møonblǿssøm Møønbørñ Mòønstrïdé Mørníngstårr
        Mýstëbrøkë M𐍈𐍈nsøng Nébülëgård Níghtstrŷdër Níghtswørd Nightwíng Nøváspýrë
        Øåkbóûgh Rávenskyë Rîvërsông Rúnefrøst Rûnësprïng Rünëwéavër Sægebrŷght Séphýrøs
        𝔖ëraphfýr Shådebríght 𝔖hadowbinder Shådøwbríght Shådøwmïst Sîlvérblâde
        Sílverbolt Sílvercrëst Sírrøwýnd 𝔖kyfæll Skýførtë Skγtöuch Sølárís Sólènsýng
        Sôlstícê Sôulstëppë ẞládëwyn Stardüst Stårflåmë Starforge Stårrfølk Stårshådë
        𝔖tormbrŷght Størmflýght Sūnshådøw Sûnstønë Swíftwålkër Tëmplëflãmë Thørnëdräke
        Thûndërhëärt Thunderstrîde Tidecaller Tímëstrøm Tîmèwŷsè Vǽlkŷrësøn Væylsháðë
        Valchëmýst Vålpïne Wîldheart Wîndbørñ Wíndwhîsper Wýldewísp Wýńdspïrït 𐌰lýrïsøng
        𐌰ndræsγl 𐌰strånøvå 𐍂ävënswørd 𐍂øthmýr 𐍂ûnëløch 𐍃hädeførge 𐍃kýbrêäkër 𐍈rënblåde
    "};

    let strs = S.split_whitespace().map(str::trim).collect::<Box<[&str]>>();
    assert_eq!(strs.len(), LAST_NAMES_CNT);
    strs
});

//=================================================================================================|

pub struct Personae(Hash<Consuming>);

impl Personae {
    pub const CNT_PERSONAE_L2: u16 = FIRST_NAMES_CNT_L2 as u16 + LAST_NAMES_CNT_L2 as u16;
    pub const CNT_PERSONAE: usize = 1 << Self::CNT_PERSONAE_L2;
    pub const IX_LAST: PersonaIx = (Self::CNT_PERSONAE - 1) as PersonaIx;
    pub const IX_RANGEINCLUSIVE: std::ops::RangeInclusive<PersonaIx> = 0..=Self::IX_LAST;

    pub const fn from_seed_u64(seed: u64) -> Personae {
        const H: Hash<Ready> = Hash::<Ready>::DEFAULT.consume_bytes(b"Personae").close();
        let h = H
            .consume_bytes(&seed.to_le_bytes())
            .close()
            .consume_bytes(b"");
        Self(h)
    }

    pub const fn get<'a>(&'a self, ix: PersonaIx) -> Option<Persona<'a>> {
        if ix <= Self::IX_LAST {
            Some(Persona { personae: self, ix })
        } else {
            None
        }
    }
}

const_assert_eq!(
    Personae::IX_LAST as u128 + 1,
    Personae::CNT_PERSONAE as u128
);

//-------------------------------------------------------------------------------------------------|

type PersonaIx = u16;

pub struct Persona<'a> {
    personae: &'a Personae,
    ix: PersonaIx,
}

impl<'a> Persona<'a> {
    pub fn first_name(&self) -> &'static str {
        "" //? TODO
    }
    pub fn last_name(&self) -> &'static str {
        "" //? TODO
    }
}

//=================================================================================================|

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod t {
    use std::{borrow::Borrow, collections::BTreeSet};

    use super::*;
    use fnv::FnvHashSet;
    use insta::{assert_json_snapshot, assert_ron_snapshot, assert_snapshot};
    use itertools::Itertools;
    use sha2::{Digest, Sha256};

    fn normalize_name<S: AsRef<str>>(s: S) -> String {
        use unicode_normalization::UnicodeNormalization;

        let s: String = s.as_ref().nfc().collect();
        s.trim().into()
    }

    fn sort(v: &mut Vec<String>) {
        use icu_collator::*;
        use icu_locid::locale;
        use std::cmp::Ordering;

        let locale_en = locale!("en").into();
        let mut options = CollatorOptions::new();
        options.strength = Some(Strength::Primary);
        let collator_en: Collator = Collator::try_new(&locale_en, options).unwrap();

        // Bubble sort. (Sorry). The Rust std sort implementations will panic if the
        // element comparison doesn't obey a consistent total ordering.
        if 2 <= v.len() {
            loop {
                let mut keep_going = false;
                for ix in 1..v.len() {
                    if collator_en.compare(&v[ix - 1], &v[ix]) == Ordering::Greater {
                        v.swap(ix - 1, ix);
                        keep_going = true;
                    }
                }
                if !keep_going {
                    break;
                }
            }
        }

        v.dedup();
    }

    fn clean_names<II>(iterable: II) -> Vec<String>
    where
        II: IntoIterator,
        II::Item: AsRef<str>,
    {
        // Normalize them
        let mut v_names: Vec<String> = iterable
            .into_iter()
            .map(|ds| normalize_name(ds.as_ref()))
            .collect();

        // Normalize and sort them
        sort(&mut v_names);

        // Verify there are no duplicates.
        let hashset_names: FnvHashSet<&str> = v_names.iter().map(|s| s.as_str()).collect();

        v_names
    }

    #[test]
    fn t1_first_names() {
        let v_names = clean_names(&*FIRST_NAMES);

        // There should be 128 of them.
        assert_snapshot!(FIRST_NAMES.len() as isize - 128, @"0");

        // There should have been no duplicates.
        assert_snapshot!(v_names.len() as isize - FIRST_NAMES.len() as isize, @"0");

        // Join them all into a String
        let mut s: String = v_names.iter().join(" ");

        // Notice if it changes.
        let hv = Sha256::digest(s.as_bytes());
        let hv = base16ct::upper::encode_string(&hv);
        assert_snapshot!(hv, @"AA6FD23521BBA048A386536B432D554431B8DEB5A6EBA241E2C879051A4B12E6");

        // Uncomment this to easily reformat the source text with 'cargo insta test --review'
        //textwrap::fill_inplace(&mut s, 80);
        //assert_snapshot!(s, @r#""#);

        // Uncomment this to check for visually similar with 'cargo insta test --review'
        //let mut s: String = v_names.iter().join("\n");
        //assert_snapshot!(s, @r#""#);
    }

    #[test]
    fn t2_family_names() {
        let v_names = clean_names(&*LAST_NAMES);

        // There should be 128 of them.
        assert_snapshot!(LAST_NAMES.len() as isize - 128, @"0");

        // There should have been no duplicates.
        assert_snapshot!(v_names.len() as isize - LAST_NAMES.len() as isize, @"0");

        // Join them all into a String
        let mut s: String = v_names.iter().join(" ");

        // Notice if it changes.
        let hv = Sha256::digest(s.as_bytes());
        let hv = base16ct::upper::encode_string(&hv);
        assert_snapshot!(hv, @"DDCB55B9E7326980AFECAF86D8F3F4AE1DC1917DAF7F9395CF469E98B302034C");

        // Uncomment this to easily reformat the source text with 'cargo insta test --review'
        //textwrap::fill_inplace(&mut s, 80);
        //assert_snapshot!(s, @r#""#);

        // Uncomment this to check for visually similar with 'cargo insta test --review'
        //let mut s: String = v_names.iter().join("\n");
        //assert_snapshot!(s, @r#""#);
    }
}
