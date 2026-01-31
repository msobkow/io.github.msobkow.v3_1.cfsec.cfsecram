
// Description: Java 25 in-memory RAM DbIO implementation for ISOCtryLang.

/*
 *	io.github.msobkow.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	This file is part of Mark's Code Fractal CFSec.
 *	
 *	Mark's Code Fractal CFSec is available under dual commercial license from
 *	Mark Stephen Sobkow, or under the terms of the GNU Library General Public License,
 *	Version 3 or later.
 *	
 *	Mark's Code Fractal CFSec is free software: you can redistribute it and/or
 *	modify it under the terms of the GNU Library General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *	
 *	Mark's Code Fractal CFSec is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU Library General Public License
 *	along with Mark's Code Fractal CFSec.  If not, see <https://www.gnu.org/licenses/>.
 *	
 *	If you wish to modify and use this code without publishing your changes in order to
 *	tie it to proprietary code, please contact Mark Stephen Sobkow
 *	for a commercial license at mark.sobkow@gmail.com
 *	
 */

package io.github.msobkow.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import io.github.msobkow.v3_1.cflib.*;
import io.github.msobkow.v3_1.cflib.dbutil.*;

import io.github.msobkow.v3_1.cfsec.cfsec.*;
import io.github.msobkow.v3_1.cfsec.cfsec.buff.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamISOCtryLangTable in-memory RAM DbIO implementation
 *	for ISOCtryLang.
 */
public class CFSecRamISOCtryLangTable
	implements ICFSecISOCtryLangTable
{
	private ICFSecSchema schema;
	private Map< ICFSecISOCtryLangPKey,
				CFSecBuffISOCtryLang > dictByPKey
		= new HashMap< ICFSecISOCtryLangPKey,
				CFSecBuffISOCtryLang >();
	private Map< CFSecBuffISOCtryLangByCtryIdxKey,
				Map< CFSecBuffISOCtryLangPKey,
					CFSecBuffISOCtryLang >> dictByCtryIdx
		= new HashMap< CFSecBuffISOCtryLangByCtryIdxKey,
				Map< CFSecBuffISOCtryLangPKey,
					CFSecBuffISOCtryLang >>();
	private Map< CFSecBuffISOCtryLangByLangIdxKey,
				Map< CFSecBuffISOCtryLangPKey,
					CFSecBuffISOCtryLang >> dictByLangIdx
		= new HashMap< CFSecBuffISOCtryLangByLangIdxKey,
				Map< CFSecBuffISOCtryLangPKey,
					CFSecBuffISOCtryLang >>();

	public CFSecRamISOCtryLangTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffISOCtryLang ensureRec(ICFSecISOCtryLang rec) {
		if (rec == null) {
			return( null );
		}
		else {
			int classCode = rec.getClassCode();
			if (classCode == ICFSecISOCtryLang.CLASS_CODE) {
				return( ((CFSecBuffISOCtryLangDefaultFactory)(schema.getFactoryISOCtryLang())).ensureRec((ICFSecISOCtryLang)rec) );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), "ensureRec", "rec", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	public ICFSecISOCtryLang createISOCtryLang( ICFSecAuthorization Authorization,
		ICFSecISOCtryLang iBuff )
	{
		final String S_ProcName = "createISOCtryLang";
		
		CFSecBuffISOCtryLang Buff = (CFSecBuffISOCtryLang)ensureRec(iBuff);
		CFSecBuffISOCtryLangPKey pkey = (CFSecBuffISOCtryLangPKey)(schema.getFactoryISOCtryLang().newPKey());
		pkey.setRequiredContainerCtry( Buff.getRequiredISOCtryId() );
		pkey.setRequiredParentLang( Buff.getRequiredISOLangId() );
		Buff.setRequiredContainerCtry( pkey.getRequiredISOCtryId() );
		Buff.setRequiredParentLang( pkey.getRequiredISOLangId() );
		CFSecBuffISOCtryLangByCtryIdxKey keyCtryIdx = (CFSecBuffISOCtryLangByCtryIdxKey)schema.getFactoryISOCtryLang().newByCtryIdxKey();
		keyCtryIdx.setRequiredISOCtryId( Buff.getRequiredISOCtryId() );

		CFSecBuffISOCtryLangByLangIdxKey keyLangIdx = (CFSecBuffISOCtryLangByLangIdxKey)schema.getFactoryISOCtryLang().newByLangIdxKey();
		keyLangIdx.setRequiredISOLangId( Buff.getRequiredISOLangId() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableISOCtry().readDerivedByIdIdx( Authorization,
						Buff.getRequiredISOCtryId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"Container",
						"ISOCtryLangCtry",
						"ISOCtryLangCtry",
						"ISOCtry",
						"ISOCtry",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecBuffISOCtryLangPKey, CFSecBuffISOCtryLang > subdictCtryIdx;
		if( dictByCtryIdx.containsKey( keyCtryIdx ) ) {
			subdictCtryIdx = dictByCtryIdx.get( keyCtryIdx );
		}
		else {
			subdictCtryIdx = new HashMap< CFSecBuffISOCtryLangPKey, CFSecBuffISOCtryLang >();
			dictByCtryIdx.put( keyCtryIdx, subdictCtryIdx );
		}
		subdictCtryIdx.put( pkey, Buff );

		Map< CFSecBuffISOCtryLangPKey, CFSecBuffISOCtryLang > subdictLangIdx;
		if( dictByLangIdx.containsKey( keyLangIdx ) ) {
			subdictLangIdx = dictByLangIdx.get( keyLangIdx );
		}
		else {
			subdictLangIdx = new HashMap< CFSecBuffISOCtryLangPKey, CFSecBuffISOCtryLang >();
			dictByLangIdx.put( keyLangIdx, subdictLangIdx );
		}
		subdictLangIdx.put( pkey, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecISOCtryLang.CLASS_CODE) {
				CFSecBuffISOCtryLang retbuff = ((CFSecBuffISOCtryLang)(schema.getFactoryISOCtryLang().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	public ICFSecISOCtryLang readDerived( ICFSecAuthorization Authorization,
		short ISOCtryId,
		short ISOLangId )
	{
		CFSecBuffISOCtryLangPKey key = (CFSecBuffISOCtryLangPKey)(schema.getFactoryISOCtryLang().newPKey());
		key.setRequiredContainerCtry( ISOCtryId );
		key.setRequiredParentLang( ISOLangId );
		return( readDerived( Authorization, key ) );
	}

	public ICFSecISOCtryLang readDerived( ICFSecAuthorization Authorization,
		ICFSecISOCtryLangPKey PKey )
	{
		final String S_ProcName = "CFSecRamISOCtryLang.readDerived";
		CFSecBuffISOCtryLangPKey key = (CFSecBuffISOCtryLangPKey)(schema.getFactoryISOCtryLang().newPKey());
		key.setRequiredContainerCtry( PKey.getRequiredISOCtryId() );
		key.setRequiredParentLang( PKey.getRequiredISOLangId() );
		ICFSecISOCtryLang buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOCtryLang lockDerived( ICFSecAuthorization Authorization,
		ICFSecISOCtryLangPKey PKey )
	{
		final String S_ProcName = "CFSecRamISOCtryLang.lockDerived";
		CFSecBuffISOCtryLangPKey key = (CFSecBuffISOCtryLangPKey)(schema.getFactoryISOCtryLang().newPKey());
		key.setRequiredContainerCtry( PKey.getRequiredISOCtryId() );
		key.setRequiredParentLang( PKey.getRequiredISOLangId() );
		ICFSecISOCtryLang buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOCtryLang[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamISOCtryLang.readAllDerived";
		ICFSecISOCtryLang[] retList = new ICFSecISOCtryLang[ dictByPKey.values().size() ];
		Iterator< CFSecBuffISOCtryLang > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public ICFSecISOCtryLang[] readDerivedByCtryIdx( ICFSecAuthorization Authorization,
		short ISOCtryId )
	{
		final String S_ProcName = "CFSecRamISOCtryLang.readDerivedByCtryIdx";
		CFSecBuffISOCtryLangByCtryIdxKey key = (CFSecBuffISOCtryLangByCtryIdxKey)schema.getFactoryISOCtryLang().newByCtryIdxKey();

		key.setRequiredISOCtryId( ISOCtryId );
		ICFSecISOCtryLang[] recArray;
		if( dictByCtryIdx.containsKey( key ) ) {
			Map< CFSecBuffISOCtryLangPKey, CFSecBuffISOCtryLang > subdictCtryIdx
				= dictByCtryIdx.get( key );
			recArray = new ICFSecISOCtryLang[ subdictCtryIdx.size() ];
			Iterator< CFSecBuffISOCtryLang > iter = subdictCtryIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffISOCtryLangPKey, CFSecBuffISOCtryLang > subdictCtryIdx
				= new HashMap< CFSecBuffISOCtryLangPKey, CFSecBuffISOCtryLang >();
			dictByCtryIdx.put( key, subdictCtryIdx );
			recArray = new ICFSecISOCtryLang[0];
		}
		return( recArray );
	}

	public ICFSecISOCtryLang[] readDerivedByLangIdx( ICFSecAuthorization Authorization,
		short ISOLangId )
	{
		final String S_ProcName = "CFSecRamISOCtryLang.readDerivedByLangIdx";
		CFSecBuffISOCtryLangByLangIdxKey key = (CFSecBuffISOCtryLangByLangIdxKey)schema.getFactoryISOCtryLang().newByLangIdxKey();

		key.setRequiredISOLangId( ISOLangId );
		ICFSecISOCtryLang[] recArray;
		if( dictByLangIdx.containsKey( key ) ) {
			Map< CFSecBuffISOCtryLangPKey, CFSecBuffISOCtryLang > subdictLangIdx
				= dictByLangIdx.get( key );
			recArray = new ICFSecISOCtryLang[ subdictLangIdx.size() ];
			Iterator< CFSecBuffISOCtryLang > iter = subdictLangIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffISOCtryLangPKey, CFSecBuffISOCtryLang > subdictLangIdx
				= new HashMap< CFSecBuffISOCtryLangPKey, CFSecBuffISOCtryLang >();
			dictByLangIdx.put( key, subdictLangIdx );
			recArray = new ICFSecISOCtryLang[0];
		}
		return( recArray );
	}

	public ICFSecISOCtryLang readDerivedByIdIdx( ICFSecAuthorization Authorization,
		short ISOCtryId,
		short ISOLangId )
	{
		final String S_ProcName = "CFSecRamISOCtryLang.readDerivedByIdIdx() ";
		CFSecBuffISOCtryLangPKey key = (CFSecBuffISOCtryLangPKey)(schema.getFactoryISOCtryLang().newPKey());
		key.setRequiredContainerCtry( ISOCtryId );
		key.setRequiredParentLang( ISOLangId );
		ICFSecISOCtryLang buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOCtryLang readRec( ICFSecAuthorization Authorization,
		short ISOCtryId,
		short ISOLangId )
	{
		CFSecBuffISOCtryLangPKey key = (CFSecBuffISOCtryLangPKey)(schema.getFactoryISOCtryLang().newPKey());
		key.setRequiredContainerCtry( ISOCtryId );
		key.setRequiredParentLang( ISOLangId );
		return( readRec( Authorization, key ) );
	}

	public ICFSecISOCtryLang readRec( ICFSecAuthorization Authorization,
		ICFSecISOCtryLangPKey PKey )
	{
		final String S_ProcName = "CFSecRamISOCtryLang.readRec";
		ICFSecISOCtryLang buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecISOCtryLang.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOCtryLang lockRec( ICFSecAuthorization Authorization,
		ICFSecISOCtryLangPKey PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecISOCtryLang buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecISOCtryLang.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOCtryLang[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamISOCtryLang.readAllRec";
		ICFSecISOCtryLang buff;
		ArrayList<ICFSecISOCtryLang> filteredList = new ArrayList<ICFSecISOCtryLang>();
		ICFSecISOCtryLang[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecISOCtryLang.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecISOCtryLang[0] ) );
	}

	public ICFSecISOCtryLang readRecByIdIdx( ICFSecAuthorization Authorization,
		short ISOCtryId,
		short ISOLangId )
	{
		final String S_ProcName = "CFSecRamISOCtryLang.readRecByIdIdx() ";
		ICFSecISOCtryLang buff = readDerivedByIdIdx( Authorization,
			ISOCtryId,
			ISOLangId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecISOCtryLang.CLASS_CODE ) ) {
			return( (ICFSecISOCtryLang)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecISOCtryLang[] readRecByCtryIdx( ICFSecAuthorization Authorization,
		short ISOCtryId )
	{
		final String S_ProcName = "CFSecRamISOCtryLang.readRecByCtryIdx() ";
		ICFSecISOCtryLang buff;
		ArrayList<ICFSecISOCtryLang> filteredList = new ArrayList<ICFSecISOCtryLang>();
		ICFSecISOCtryLang[] buffList = readDerivedByCtryIdx( Authorization,
			ISOCtryId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecISOCtryLang.CLASS_CODE ) ) {
				filteredList.add( (ICFSecISOCtryLang)buff );
			}
		}
		return( filteredList.toArray( new ICFSecISOCtryLang[0] ) );
	}

	public ICFSecISOCtryLang[] readRecByLangIdx( ICFSecAuthorization Authorization,
		short ISOLangId )
	{
		final String S_ProcName = "CFSecRamISOCtryLang.readRecByLangIdx() ";
		ICFSecISOCtryLang buff;
		ArrayList<ICFSecISOCtryLang> filteredList = new ArrayList<ICFSecISOCtryLang>();
		ICFSecISOCtryLang[] buffList = readDerivedByLangIdx( Authorization,
			ISOLangId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecISOCtryLang.CLASS_CODE ) ) {
				filteredList.add( (ICFSecISOCtryLang)buff );
			}
		}
		return( filteredList.toArray( new ICFSecISOCtryLang[0] ) );
	}

	public ICFSecISOCtryLang updateISOCtryLang( ICFSecAuthorization Authorization,
		ICFSecISOCtryLang iBuff )
	{
		CFSecBuffISOCtryLang Buff = (CFSecBuffISOCtryLang)ensureRec(iBuff);
		CFSecBuffISOCtryLangPKey pkey = (CFSecBuffISOCtryLangPKey)(schema.getFactoryISOCtryLang().newPKey());
		pkey.setRequiredContainerCtry( Buff.getRequiredISOCtryId() );
		pkey.setRequiredParentLang( Buff.getRequiredISOLangId() );
		CFSecBuffISOCtryLang existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateISOCtryLang",
				"Existing record not found",
				"Existing record not found",
				"ISOCtryLang",
				"ISOCtryLang",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateISOCtryLang",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffISOCtryLangByCtryIdxKey existingKeyCtryIdx = (CFSecBuffISOCtryLangByCtryIdxKey)schema.getFactoryISOCtryLang().newByCtryIdxKey();
		existingKeyCtryIdx.setRequiredISOCtryId( existing.getRequiredISOCtryId() );

		CFSecBuffISOCtryLangByCtryIdxKey newKeyCtryIdx = (CFSecBuffISOCtryLangByCtryIdxKey)schema.getFactoryISOCtryLang().newByCtryIdxKey();
		newKeyCtryIdx.setRequiredISOCtryId( Buff.getRequiredISOCtryId() );

		CFSecBuffISOCtryLangByLangIdxKey existingKeyLangIdx = (CFSecBuffISOCtryLangByLangIdxKey)schema.getFactoryISOCtryLang().newByLangIdxKey();
		existingKeyLangIdx.setRequiredISOLangId( existing.getRequiredISOLangId() );

		CFSecBuffISOCtryLangByLangIdxKey newKeyLangIdx = (CFSecBuffISOCtryLangByLangIdxKey)schema.getFactoryISOCtryLang().newByLangIdxKey();
		newKeyLangIdx.setRequiredISOLangId( Buff.getRequiredISOLangId() );

		// Check unique indexes

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableISOCtry().readDerivedByIdIdx( Authorization,
						Buff.getRequiredISOCtryId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateISOCtryLang",
						"Container",
						"Container",
						"ISOCtryLangCtry",
						"ISOCtryLangCtry",
						"ISOCtry",
						"ISOCtry",
						null );
				}
			}
		}

		// Update is valid

		Map< CFSecBuffISOCtryLangPKey, CFSecBuffISOCtryLang > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictByCtryIdx.get( existingKeyCtryIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByCtryIdx.containsKey( newKeyCtryIdx ) ) {
			subdict = dictByCtryIdx.get( newKeyCtryIdx );
		}
		else {
			subdict = new HashMap< CFSecBuffISOCtryLangPKey, CFSecBuffISOCtryLang >();
			dictByCtryIdx.put( newKeyCtryIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByLangIdx.get( existingKeyLangIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByLangIdx.containsKey( newKeyLangIdx ) ) {
			subdict = dictByLangIdx.get( newKeyLangIdx );
		}
		else {
			subdict = new HashMap< CFSecBuffISOCtryLangPKey, CFSecBuffISOCtryLang >();
			dictByLangIdx.put( newKeyLangIdx, subdict );
		}
		subdict.put( pkey, Buff );

		return(Buff);
	}

	public void deleteISOCtryLang( ICFSecAuthorization Authorization,
		ICFSecISOCtryLang iBuff )
	{
		final String S_ProcName = "CFSecRamISOCtryLangTable.deleteISOCtryLang() ";
		CFSecBuffISOCtryLang Buff = (CFSecBuffISOCtryLang)ensureRec(iBuff);
		int classCode;
		CFSecBuffISOCtryLangPKey pkey = (CFSecBuffISOCtryLangPKey)(Buff.getPKey());
		CFSecBuffISOCtryLang existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteISOCtryLang",
				pkey );
		}
		CFSecBuffISOCtryLangByCtryIdxKey keyCtryIdx = (CFSecBuffISOCtryLangByCtryIdxKey)schema.getFactoryISOCtryLang().newByCtryIdxKey();
		keyCtryIdx.setRequiredISOCtryId( existing.getRequiredISOCtryId() );

		CFSecBuffISOCtryLangByLangIdxKey keyLangIdx = (CFSecBuffISOCtryLangByLangIdxKey)schema.getFactoryISOCtryLang().newByLangIdxKey();
		keyLangIdx.setRequiredISOLangId( existing.getRequiredISOLangId() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecBuffISOCtryLangPKey, CFSecBuffISOCtryLang > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByCtryIdx.get( keyCtryIdx );
		subdict.remove( pkey );

		subdict = dictByLangIdx.get( keyLangIdx );
		subdict.remove( pkey );

	}
	public void deleteISOCtryLangByIdIdx( ICFSecAuthorization Authorization,
		short ISOCtryId,
		short ISOLangId )
	{
		CFSecBuffISOCtryLangPKey key = (CFSecBuffISOCtryLangPKey)(schema.getFactoryISOCtryLang().newPKey());
		key.setRequiredContainerCtry( ISOCtryId );
		key.setRequiredParentLang( ISOLangId );
		deleteISOCtryLangByIdIdx( Authorization, key );
	}

	public void deleteISOCtryLangByIdIdx( ICFSecAuthorization Authorization,
		ICFSecISOCtryLangPKey PKey )
	{
		CFSecBuffISOCtryLangPKey key = (CFSecBuffISOCtryLangPKey)(schema.getFactoryISOCtryLang().newPKey());
		key.setRequiredContainerCtry( PKey.getRequiredISOCtryId() );
		key.setRequiredParentLang( PKey.getRequiredISOLangId() );
		CFSecBuffISOCtryLangPKey argKey = key;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffISOCtryLang cur;
		LinkedList<CFSecBuffISOCtryLang> matchSet = new LinkedList<CFSecBuffISOCtryLang>();
		Iterator<CFSecBuffISOCtryLang> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffISOCtryLang> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffISOCtryLang)(schema.getTableISOCtryLang().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOCtryId(),
				cur.getRequiredISOLangId() ));
			deleteISOCtryLang( Authorization, cur );
		}
	}

	public void deleteISOCtryLangByCtryIdx( ICFSecAuthorization Authorization,
		short argISOCtryId )
	{
		CFSecBuffISOCtryLangByCtryIdxKey key = (CFSecBuffISOCtryLangByCtryIdxKey)schema.getFactoryISOCtryLang().newByCtryIdxKey();
		key.setRequiredISOCtryId( argISOCtryId );
		deleteISOCtryLangByCtryIdx( Authorization, key );
	}

	public void deleteISOCtryLangByCtryIdx( ICFSecAuthorization Authorization,
		ICFSecISOCtryLangByCtryIdxKey argKey )
	{
		CFSecBuffISOCtryLang cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffISOCtryLang> matchSet = new LinkedList<CFSecBuffISOCtryLang>();
		Iterator<CFSecBuffISOCtryLang> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffISOCtryLang> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffISOCtryLang)(schema.getTableISOCtryLang().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOCtryId(),
				cur.getRequiredISOLangId() ));
			deleteISOCtryLang( Authorization, cur );
		}
	}

	public void deleteISOCtryLangByLangIdx( ICFSecAuthorization Authorization,
		short argISOLangId )
	{
		CFSecBuffISOCtryLangByLangIdxKey key = (CFSecBuffISOCtryLangByLangIdxKey)schema.getFactoryISOCtryLang().newByLangIdxKey();
		key.setRequiredISOLangId( argISOLangId );
		deleteISOCtryLangByLangIdx( Authorization, key );
	}

	public void deleteISOCtryLangByLangIdx( ICFSecAuthorization Authorization,
		ICFSecISOCtryLangByLangIdxKey argKey )
	{
		CFSecBuffISOCtryLang cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffISOCtryLang> matchSet = new LinkedList<CFSecBuffISOCtryLang>();
		Iterator<CFSecBuffISOCtryLang> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffISOCtryLang> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffISOCtryLang)(schema.getTableISOCtryLang().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOCtryId(),
				cur.getRequiredISOLangId() ));
			deleteISOCtryLang( Authorization, cur );
		}
	}
}
