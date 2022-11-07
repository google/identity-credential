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

package com.android.identity;

import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.List;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Number;
import co.nstant.in.cbor.model.SimpleValue;
import co.nstant.in.cbor.model.SimpleValueType;

public class OriginInfoNfc extends OriginInfo {
    private static final String TAG = "OriginInfoNfc";

    static final int TYPE = 3;
    private final long mCat;

    public OriginInfoNfc(long cat) {
        mCat = cat;
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

    @NonNull
    @Override
    DataItem encode() {
        return new CborBuilder()
                .addArray()
                .add(mCat)
                .add(TYPE)
                .add(SimpleValue.NULL)
                .end()
                .build().get(0);
    }

    @Nullable
    static OriginInfoNfc decode(@NonNull DataItem oiDataItem) {
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
        if (!(items.get(2) instanceof SimpleValue) ||
                ((SimpleValue) items.get(2)).getSimpleValueType() != SimpleValueType.NULL) {
            throw new IllegalArgumentException("Details is not a NULL value");
        }
        long cat = ((Number) items.get(0)).getValue().longValue();
        long type = ((Number) items.get(1)).getValue().longValue();
        if (type != TYPE) {
            Log.w(TAG, "Unexpected type " + type);
            return null;
        }
        return new OriginInfoNfc(cat);
    }
}
