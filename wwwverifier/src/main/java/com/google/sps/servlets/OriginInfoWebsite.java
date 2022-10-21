/*
 * Copyright 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.sps.servlets;

//import android.util.Log;

//import androidx.annotation.NonNull;
//import androidx.annotation.Nullable;

import java.util.List;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.Number;

public class OriginInfoWebsite extends OriginInfo {
    private static final String TAG = "OriginInfoWebsite";

    static final int TYPE = 1;
    private final long mCat;
    private final String mBaseUrl;

    public OriginInfoWebsite(long cat, String baseUrl) {
        mCat = cat;
        mBaseUrl = baseUrl;
    }

    /**
     * Specifies whether the OriginInfoOptions are about this engagement or the one
     * received previously
     *
     * @return one of {@link #CAT_DELIVERY} or {@link #CAT_RECEIVE}.
     */
    @Override
    public long getCat() {
        return mCat;
    }

    public String getBaseUrl() {
        return mBaseUrl;
    }

    @Override
    DataItem encode() {
        return new CborBuilder()
                .addArray()
                .add(mCat)
                .add(TYPE)
                .addMap()
                .put("baseUrl", mBaseUrl)
                .end()
                .end()
                .build().get(0);
    }

    static OriginInfoWebsite decode(DataItem oiDataItem) {
        if (!(oiDataItem instanceof co.nstant.in.cbor.model.Array)) {
            throw new IllegalArgumentException("Top-level CBOR is not an array");
        }
        List<DataItem> items = ((Array) oiDataItem).getDataItems();
        if (items.size() != 3) {
            throw new IllegalArgumentException("Expected array with 3 elements, got " + items.size());
        }
        if (!(items.get(0) instanceof Number) || !(items.get(1) instanceof Number)) {
            throw new IllegalArgumentException("First two items are not numbers");
        }
        if (!(items.get(2) instanceof Map)) {
            throw new IllegalArgumentException("Details is not a map");
        }
        Map details = (Map) items.get(2);
        long cat = ((Number) items.get(0)).getValue().longValue();
        long type = ((Number) items.get(1)).getValue().longValue();
        String baseUrl = Util.cborMapExtractString(details, "baseUrl");
        if (type != TYPE) {
            //Log.w(TAG, "Unexpected type " + type);
            return null;
        }
        return new OriginInfoWebsite(cat, baseUrl);
    }
}